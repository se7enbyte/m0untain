//! Windows Filtering Platform backend (user-mode, no kernel driver).
//!
//! Responsibilities:
//!   * open a WFP engine session and register a dedicated sublayer,
//!   * install/remove temporary BLOCK filters for offending IPs (enforcement),
//!   * subscribe to net events and forward inbound connection attempts to the
//!     detection pipeline as `RawConn`.
//!
//! Requires the process to run **elevated** (WFP filter management needs
//! administrator rights). The installer requests elevation; during `tauri dev`
//! start your terminal as administrator.
//!
//! COMPILE NOTE: the block/unblock path uses the stable `*0` WFP APIs. The net
//! event subscription uses `FwpmNetEventSubscribe4` + `FWPM_NET_EVENT5`, which
//! is correct on Windows 10/11. If your installed `windows` crate exposes a
//! different newest version, adjust the `Subscribe4`/`FWPM_NET_EVENT5` suffixes
//! and the callback signature to match — enforcement is unaffected.

#![allow(non_snake_case, clippy::field_reassign_with_default)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetLengthSid, IsValidSid, LookupAccountSidW, PSID, SID, SID_NAME_USE,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::{AppProtocol, Firewall, RawConn, RemoteMatch};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn app_id_from_path(path: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let err = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob) };
    if err != ERROR_SUCCESS.0 || blob.is_null() {
        return None;
    }
    let bytes = unsafe {
        let blob_ref = &*blob;
        if blob_ref.data.is_null() || blob_ref.size == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(blob_ref.data, blob_ref.size as usize).to_vec()
        }
    };
    unsafe {
        let mut ptr = blob as *mut core::ffi::c_void;
        FwpmFreeMemory0(&mut ptr);
    }
    (!bytes.is_empty()).then_some(bytes)
}

unsafe fn sid_bytes(sid: *mut windows::Win32::Security::SID) -> Option<Vec<u8>> {
    if sid.is_null() {
        return None;
    }
    let psid = PSID(sid as *mut core::ffi::c_void);
    if !IsValidSid(psid).as_bool() {
        return None;
    }
    let len = GetLengthSid(psid);
    if len == 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(sid as *const u8, len as usize).to_vec())
}

unsafe fn sid_string(sid: *mut windows::Win32::Security::SID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let psid = PSID(sid as *mut core::ffi::c_void);
    let mut ptr = PWSTR::null();
    ConvertSidToStringSidW(psid, &mut ptr).ok()?;
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.0.add(len) != 0 {
        len += 1;
    }
    let value = String::from_utf16_lossy(std::slice::from_raw_parts(ptr.0, len));
    let _ = LocalFree(HLOCAL(ptr.0 as *mut core::ffi::c_void));
    Some(value)
}

unsafe fn sid_account_name(sid: *mut windows::Win32::Security::SID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let psid = PSID(sid as *mut core::ffi::c_void);
    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_use = SID_NAME_USE(0);
    let _ = LookupAccountSidW(
        PCWSTR::null(),
        psid,
        PWSTR::null(),
        &mut name_len,
        PWSTR::null(),
        &mut domain_len,
        &mut sid_use,
    );
    if name_len == 0 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    LookupAccountSidW(
        PCWSTR::null(),
        psid,
        PWSTR(name.as_mut_ptr()),
        &mut name_len,
        PWSTR(domain.as_mut_ptr()),
        &mut domain_len,
        &mut sid_use,
    )
    .ok()?;
    let clean = |buf: &[u16]| {
        let end = buf.iter().position(|ch| *ch == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    };
    let name = clean(&name);
    let domain = clean(&domain);
    if name.trim().is_empty() {
        None
    } else if domain.trim().is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}

// Our own provider/sublayer GUIDs so we can find and clean up only our filters.
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6d0a_9f3e_11c4_47a8_9c2e_5b7a_1e0f_9c11);

/// Global channel to the pipeline, set once so the C callback can reach it.
static EVENT_TX: OnceLock<Sender<RawConn>> = OnceLock::new();

pub struct WfpFirewall {
    engine: HANDLE,
    // our block handle -> the concrete WFP filter ids we installed for it
    filters: Mutex<HashMap<u64, Vec<u64>>>,
    next_handle: Mutex<u64>,
    _sub_handle: usize,
}

// HANDLE isn't Sync by default; we guard all mutating use and never move the
// raw engine across threads except read-only for enum/delete under the lock.
unsafe impl Send for WfpFirewall {}
unsafe impl Sync for WfpFirewall {}

enum WfpIdentity<'a> {
    AppId(&'a [u8]),
    PackageSid(&'a [u8]),
}

impl WfpFirewall {
    pub fn start(tx: Sender<RawConn>) -> Result<Self, String> {
        let _ = EVENT_TX.set(tx);
        unsafe {
            let mut engine = HANDLE::default();
            // Open a dynamic session: all our filters auto-delete when the
            // process exits, so a crash never leaves the machine filtered.
            let mut session = FWPM_SESSION0::default();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let err = FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine);
            if err != ERROR_SUCCESS.0 {
                return Err(format!("FwpmEngineOpen0 failed: {err}"));
            }

            // Register our sublayer (idempotent; ignore "already exists").
            let mut sublayer = FWPM_SUBLAYER0::default();
            sublayer.subLayerKey = SUBLAYER_KEY;
            let name = windows::core::w!("m0untain dynamic blocks");
            sublayer.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut _);
            sublayer.weight = 0x8000;
            let sublayer_error = FwpmSubLayerAdd0(engine, &sublayer, None);
            if sublayer_error != ERROR_SUCCESS.0 {
                let _ = FwpmEngineClose0(engine);
                return Err(format!(
                    "FwpmSubLayerAdd0 failed: {sublayer_error}. Run m0untain as administrator."
                ));
            }

            let sub_handle = subscribe_net_events(engine).unwrap_or(0);

            Ok(WfpFirewall {
                engine,
                filters: Mutex::new(HashMap::new()),
                next_handle: Mutex::new(1),
                _sub_handle: sub_handle,
            })
        }
    }

    /// Add one BLOCK filter at `layer` matching remote address `ip`.
    unsafe fn add_block_filter(&self, ip: IpAddr, layer: GUID) -> Result<u64, String> {
        let mut cond = FWPM_FILTER_CONDITION0::default();
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;

        // Fill the condition value according to address family.
        let mut v6_storage: FWP_BYTE_ARRAY16;
        match ip {
            IpAddr::V4(v4) => {
                cond.conditionValue.r#type = FWP_UINT32;
                // WFP expects the IPv4 address as a host-order u32.
                cond.conditionValue.Anonymous.uint32 = u32::from_be_bytes(v4.octets());
            }
            IpAddr::V6(v6) => {
                cond.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                v6_storage = FWP_BYTE_ARRAY16 {
                    byteArray16: v6.octets(),
                };
                cond.conditionValue.Anonymous.byteArray16 = &mut v6_storage;
            }
        }

        let mut filter = FWPM_FILTER0::default();
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 15; // high, above default rules
        filter.numFilterConditions = 1;
        filter.filterCondition = &mut cond;
        filter.action.r#type = FWP_ACTION_BLOCK;
        let name = windows::core::w!("m0untain block");
        filter.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut _);

        let mut id: u64 = 0;
        let err = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
        if err != ERROR_SUCCESS.0 {
            return Err(format!("FwpmFilterAdd0 failed: {err}"));
        }
        Ok(id)
    }

    /// Add an outbound ALE block for one application/package identifier.
    unsafe fn add_identity_block_filter(
        &self,
        identity: WfpIdentity<'_>,
        layer: GUID,
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<Option<u64>, String> {
        let identity_len = match identity {
            WfpIdentity::AppId(app_id) => app_id.len(),
            WfpIdentity::PackageSid(package_sid) => package_sid.len(),
        };
        if identity_len == 0 || identity_len > u32::MAX as usize {
            return Err("invalid WFP application/package identifier".to_string());
        }
        if !target_matches_layer(remote, layer) {
            return Ok(None);
        }

        let mut blob = FWP_BYTE_BLOB::default();
        let mut conditions = Vec::with_capacity(4);
        let mut v6_storage: FWP_BYTE_ARRAY16;
        let mut v4_mask_storage: FWP_V4_ADDR_AND_MASK;
        let mut v6_mask_storage: FWP_V6_ADDR_AND_MASK;

        let mut identity_condition = FWPM_FILTER_CONDITION0::default();
        identity_condition.matchType = FWP_MATCH_EQUAL;
        match identity {
            WfpIdentity::AppId(app_id) => {
                blob = FWP_BYTE_BLOB {
                    size: app_id.len() as u32,
                    data: app_id.as_ptr() as *mut u8,
                };
                identity_condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                identity_condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                identity_condition.conditionValue.Anonymous.byteBlob = &mut blob;
            }
            WfpIdentity::PackageSid(package_sid) => {
                identity_condition.fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
                identity_condition.conditionValue.r#type = FWP_SID;
                identity_condition.conditionValue.Anonymous.sid = package_sid.as_ptr() as *mut SID;
            }
        }
        conditions.push(identity_condition);

        if let AppProtocol::Tcp | AppProtocol::Udp = protocol {
            let mut protocol_condition = FWPM_FILTER_CONDITION0::default();
            protocol_condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            protocol_condition.matchType = FWP_MATCH_EQUAL;
            protocol_condition.conditionValue.r#type = FWP_UINT8;
            protocol_condition.conditionValue.Anonymous.uint8 = match protocol {
                AppProtocol::Tcp => 6,
                AppProtocol::Udp => 17,
                AppProtocol::All => unreachable!(),
            };
            conditions.push(protocol_condition);
        }

        if let Some(remote) = remote {
            let mut remote_condition = FWPM_FILTER_CONDITION0::default();
            remote_condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            remote_condition.matchType = FWP_MATCH_EQUAL;
            match remote {
                RemoteMatch::Ip(IpAddr::V4(ip)) => {
                    remote_condition.conditionValue.r#type = FWP_UINT32;
                    remote_condition.conditionValue.Anonymous.uint32 =
                        u32::from_be_bytes(ip.octets());
                }
                RemoteMatch::Ip(IpAddr::V6(ip)) => {
                    remote_condition.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    v6_storage = FWP_BYTE_ARRAY16 {
                        byteArray16: ip.octets(),
                    };
                    remote_condition.conditionValue.Anonymous.byteArray16 = &mut v6_storage;
                }
                RemoteMatch::Cidr {
                    network: IpAddr::V4(network),
                    prefix,
                } => {
                    remote_condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    v4_mask_storage = FWP_V4_ADDR_AND_MASK {
                        addr: u32::from_be_bytes(network.octets()),
                        mask: ipv4_prefix_mask(prefix),
                    };
                    remote_condition.conditionValue.Anonymous.v4AddrMask = &mut v4_mask_storage;
                }
                RemoteMatch::Cidr {
                    network: IpAddr::V6(network),
                    prefix,
                } => {
                    remote_condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    v6_mask_storage = FWP_V6_ADDR_AND_MASK {
                        addr: network.octets(),
                        prefixLength: prefix,
                    };
                    remote_condition.conditionValue.Anonymous.v6AddrMask = &mut v6_mask_storage;
                }
            }
            conditions.push(remote_condition);
        }

        if let Some(port) = remote_port {
            let mut port_condition = FWPM_FILTER_CONDITION0::default();
            port_condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            port_condition.matchType = FWP_MATCH_EQUAL;
            port_condition.conditionValue.r#type = FWP_UINT16;
            port_condition.conditionValue.Anonymous.uint16 = port;
            conditions.push(port_condition);
        }

        let mut filter = FWPM_FILTER0::default();
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = 15;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.r#type = FWP_ACTION_BLOCK;
        let name = windows::core::w!("m0untain application quarantine");
        filter.displayData.name = windows::core::PWSTR(name.as_ptr() as *mut _);

        let mut id = 0;
        let err = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
        if err != ERROR_SUCCESS.0 {
            return Err(format!("FwpmFilterAdd0(app) failed: {err}"));
        }
        Ok(Some(id))
    }

    unsafe fn add_app_block_filter(
        &self,
        app_id: &[u8],
        layer: GUID,
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<Option<u64>, String> {
        self.add_identity_block_filter(
            WfpIdentity::AppId(app_id),
            layer,
            protocol,
            remote,
            remote_port,
        )
    }

    unsafe fn add_package_block_filter(
        &self,
        package_sid: &[u8],
        layer: GUID,
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<Option<u64>, String> {
        self.add_identity_block_filter(
            WfpIdentity::PackageSid(package_sid),
            layer,
            protocol,
            remote,
            remote_port,
        )
    }
}

fn ipv4_prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

fn target_matches_layer(remote: Option<RemoteMatch>, layer: GUID) -> bool {
    match remote {
        Some(RemoteMatch::Ip(IpAddr::V4(_)))
        | Some(RemoteMatch::Cidr {
            network: IpAddr::V4(_),
            ..
        }) => layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Some(RemoteMatch::Ip(IpAddr::V6(_)))
        | Some(RemoteMatch::Cidr {
            network: IpAddr::V6(_),
            ..
        }) => layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        None => true,
    }
}

impl Firewall for WfpFirewall {
    fn block_ip(&self, ip: IpAddr) -> Result<u64, String> {
        // Block both directions for the family: new outbound connects to it and
        // new inbound accepts from it.
        let (l_connect, l_accept) = match ip {
            IpAddr::V4(_) => (
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            ),
            IpAddr::V6(_) => (
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ),
        };
        let mut ids = Vec::with_capacity(2);
        unsafe {
            ids.push(self.add_block_filter(ip, l_connect)?);
            match self.add_block_filter(ip, l_accept) {
                Ok(id) => ids.push(id),
                Err(error) => {
                    for id in ids {
                        let _ = FwpmFilterDeleteById0(self.engine, id);
                    }
                    return Err(error);
                }
            }
        }
        let mut h = self.next_handle.lock().unwrap();
        let handle = *h;
        *h += 1;
        self.filters.lock().unwrap().insert(handle, ids);
        Ok(handle)
    }

    fn block_app(&self, app_id: &[u8], protocol: AppProtocol) -> Result<u64, String> {
        self.block_app_target(app_id, protocol, None, None)
    }

    fn block_package(&self, package_sid: &[u8], protocol: AppProtocol) -> Result<u64, String> {
        self.block_package_target(package_sid, protocol, None, None)
    }

    fn block_app_target(
        &self,
        app_id: &[u8],
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<u64, String> {
        let mut ids = Vec::with_capacity(2);
        unsafe {
            if let Some(id) = self.add_app_block_filter(
                app_id,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                protocol,
                remote,
                remote_port,
            )? {
                ids.push(id);
            }
            match self.add_app_block_filter(
                app_id,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                protocol,
                remote,
                remote_port,
            ) {
                Ok(Some(id)) => ids.push(id),
                Ok(None) => {}
                Err(error) => {
                    for id in ids {
                        let _ = FwpmFilterDeleteById0(self.engine, id);
                    }
                    return Err(error);
                }
            }
        }
        if ids.is_empty() {
            return Err("target does not match an ALE connect layer".to_string());
        }
        let mut next = self.next_handle.lock().unwrap();
        let handle = *next;
        *next += 1;
        self.filters.lock().unwrap().insert(handle, ids);
        Ok(handle)
    }

    fn block_package_target(
        &self,
        package_sid: &[u8],
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<u64, String> {
        let mut ids = Vec::with_capacity(2);
        unsafe {
            if let Some(id) = self.add_package_block_filter(
                package_sid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                protocol,
                remote,
                remote_port,
            )? {
                ids.push(id);
            }
            match self.add_package_block_filter(
                package_sid,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                protocol,
                remote,
                remote_port,
            ) {
                Ok(Some(id)) => ids.push(id),
                Ok(None) => {}
                Err(error) => {
                    for id in ids {
                        let _ = FwpmFilterDeleteById0(self.engine, id);
                    }
                    return Err(error);
                }
            }
        }
        if ids.is_empty() {
            return Err("target does not match an ALE connect layer".to_string());
        }
        let mut next = self.next_handle.lock().unwrap();
        let handle = *next;
        *next += 1;
        self.filters.lock().unwrap().insert(handle, ids);
        Ok(handle)
    }

    fn unblock(&self, handle: u64) -> Result<(), String> {
        let ids = self.filters.lock().unwrap().remove(&handle);
        if let Some(ids) = ids {
            let mut first_error = None;
            unsafe {
                for id in ids {
                    let err = FwpmFilterDeleteById0(self.engine, id);
                    if err != ERROR_SUCCESS.0 && first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(format!("FwpmFilterDeleteById0 failed: {error}"));
            }
        }
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "WFP"
    }
}

/// Turn on net-event collection and subscribe. See the COMPILE NOTE at the top
/// about version suffixes if this block does not match your SDK.
unsafe fn subscribe_net_events(engine: HANDLE) -> Result<usize, String> {
    // Enable collection of net events.
    let mut on = FWP_VALUE0::default();
    on.r#type = FWP_UINT32;
    on.Anonymous.uint32 = 1;
    let _ = FwpmEngineSetOption0(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &on);

    let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
    // Empty enum template = receive all event types.
    let mut handle: HANDLE = HANDLE::default();
    let err = FwpmNetEventSubscribe4(
        engine,
        &subscription,
        Some(net_event_callback),
        None,
        &mut handle,
    );
    if err != ERROR_SUCCESS.0 {
        return Err(format!("FwpmNetEventSubscribe4 failed: {err}"));
    }
    Ok(handle.0 as usize)
}

/// C callback invoked by WFP on its own worker threads. We do the minimum here:
/// pull the 5-tuple out of the header and push a `RawConn` to the pipeline.
unsafe extern "system" fn net_event_callback(
    _context: *mut core::ffi::c_void,
    event: *const FWPM_NET_EVENT5,
) {
    if event.is_null() {
        return;
    }
    let ev = &*event;
    let h = &ev.header;

    // Only classify events carry a reliable traffic direction. Other WFP
    // diagnostics (IPsec/IKE/capability events) must not feed the detector.
    let (inbound, is_new) = if ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW {
        let Some(details) = ev.Anonymous.classifyAllow.as_ref() else {
            return;
        };
        (
            details.msFwpDirection == FWP_DIRECTION_INBOUND.0 as u32,
            details.reauthReason == 0,
        )
    } else if ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        let Some(details) = ev.Anonymous.classifyDrop.as_ref() else {
            return;
        };
        (
            details.msFwpDirection == FWP_DIRECTION_INBOUND.0 as u32,
            details.reauthReason == 0,
        )
    } else {
        return;
    };

    // The address unions are only valid when WFP marks both fields as set.
    let required_flags = FWPM_NET_EVENT_FLAG_IP_VERSION_SET | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;
    if h.flags & required_flags != required_flags {
        return;
    }

    // HEADER3 keeps local and remote addresses in separate unions. In
    // windows-rs 0.58, Anonymous1 is local and Anonymous2 is remote.
    let remote_ip = if h.ipVersion == FWP_IP_VERSION_V4 {
        IpAddr::V4(std::net::Ipv4Addr::from(
            h.Anonymous2.remoteAddrV4.to_be_bytes(),
        ))
    } else if h.ipVersion == FWP_IP_VERSION_V6 {
        IpAddr::V6(std::net::Ipv6Addr::from(
            h.Anonymous2.remoteAddrV6.byteArray16,
        ))
    } else {
        return;
    };

    let (app_id, app_path) = if h.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET != 0
        && h.appId.size >= 2
        && !h.appId.data.is_null()
    {
        let bytes = std::slice::from_raw_parts(h.appId.data, h.appId.size as usize).to_vec();
        let units = std::slice::from_raw_parts(
            h.appId.data as *const u16,
            h.appId.size as usize / std::mem::size_of::<u16>(),
        );
        let end = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        (Some(bytes), Some(String::from_utf16_lossy(&units[..end])))
    } else {
        (None, None)
    };

    let (app_package_sid, app_package_sid_string, app_name) =
        if h.flags & FWPM_NET_EVENT_FLAG_PACKAGE_ID_SET != 0 && !h.packageSid.is_null() {
            (
                sid_bytes(h.packageSid),
                sid_string(h.packageSid),
                sid_account_name(h.packageSid),
            )
        } else {
            (None, None, None)
        };

    let raw = RawConn {
        ts_ms: now_ms(),
        inbound,
        is_new,
        udp: h.ipProtocol == 17,
        remote_ip,
        remote_port: h.remotePort,
        local_port: h.localPort,
        pid: 0,
        app_id,
        app_path,
        app_package_sid,
        app_package_sid_string,
        app_name,
    };
    if let Some(tx) = EVENT_TX.get() {
        let _ = tx.send(raw);
    }
}
