//! m0untain boot-time firewall service.
//!
//! The desktop app owns UI, prompts, and rule editing. This service owns the
//! early/default-deny enforcement path: it can be installed as an automatic
//! Windows service, reads the same `state.json`, and keeps WFP filters alive
//! even when the Tauri UI is closed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const SERVICE_NAME: &str = "m0untain-service";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ServiceMode {
    AppOnly,
    InstalledStopped,
    RunningDefaultDeny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub mode: ServiceMode,
    pub message: String,
}

impl ServiceStatus {
    pub fn app_only() -> Self {
        Self {
            installed: false,
            running: false,
            mode: ServiceMode::AppOnly,
            message: "Windows service is not installed yet; m0untain is enforcing app-session rules while the UI is running.".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct AppSettings {
    active_profile_id: String,
    default_deny_enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct RuleTarget {
    kind: String,
    value: String,
    port: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct ProgramRule {
    app_path: String,
    app_id: Vec<u8>,
    decision: String,
    protocol: String,
    direction: String,
    target: Option<RuleTarget>,
    expires_at_ms: Option<u64>,
    profile_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct RuleProfile {
    id: String,
    default_deny: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
struct PersistentState {
    settings: AppSettings,
    rules: HashMap<String, ProgramRule>,
    profiles: Vec<RuleProfile>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn load_state(path: &Path) -> Result<PersistentState, String> {
    let json = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&json).map_err(|error| error.to_string())
}

fn default_deny_enabled(state: &PersistentState) -> bool {
    if state.settings.default_deny_enabled {
        return true;
    }
    state
        .profiles
        .iter()
        .find(|profile| profile.id == state.settings.active_profile_id)
        .is_some_and(|profile| profile.default_deny)
}

fn rule_is_active(rule: &ProgramRule, now: u64) -> bool {
    rule.expires_at_ms.is_none_or(|expires| expires > now)
}

fn rule_in_active_scope(rule: &ProgramRule, active_profile_id: &str) -> bool {
    rule.profile_id == "global"
        || rule.profile_id == active_profile_id
        || rule.profile_id.is_empty()
}

fn parse_args_state_path() -> Option<PathBuf> {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--state" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

pub fn current_status() -> ServiceStatus {
    #[cfg(windows)]
    {
        windows_service::current_status()
    }
    #[cfg(not(windows))]
    {
        ServiceStatus::app_only()
    }
}

pub fn run() -> Result<(), String> {
    let state_path = parse_args_state_path()
        .ok_or_else(|| "--state <path-to-state.json> is required".to_string())?;
    #[cfg(windows)]
    {
        windows_service::run(state_path)
    }
    #[cfg(not(windows))]
    {
        let _ = state_path;
        Err("m0untain-service only runs as a Windows service".to_string())
    }
}

#[cfg(windows)]
mod windows_service {
    use std::ffi::OsStr;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::OnceLock;
    use std::thread;
    use std::time::Duration;

    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::*;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    use windows::Win32::System::Services::*;

    use super::{
        default_deny_enabled, load_state, now_ms, rule_in_active_scope, rule_is_active,
        PersistentState, ProgramRule, RuleTarget, ServiceStatus, SERVICE_NAME,
    };

    const SUBLAYER_KEY: GUID = GUID::from_u128(0x6d0a_9f3e_11c4_47a8_9c2e_5b7a_1e0f_9c11);
    static STOP: AtomicBool = AtomicBool::new(false);
    static STATE_PATH: OnceLock<PathBuf> = OnceLock::new();

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn current_status() -> ServiceStatus {
        // The UI does richer SCM querying. The service crate status stays
        // conservative for direct CLI/debug use.
        ServiceStatus::app_only()
    }

    pub fn run(state_path: PathBuf) -> Result<(), String> {
        let _ = STATE_PATH.set(state_path);
        let mut name = wide(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()).map_err(|error| error.to_string()) }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        let name = wide(SERVICE_NAME);
        let Ok(handle) = RegisterServiceCtrlHandlerW(PCWSTR(name.as_ptr()), Some(control_handler))
        else {
            return;
        };
        set_status(handle, SERVICE_START_PENDING, 0);
        let path = STATE_PATH.get().cloned();
        set_status(handle, SERVICE_RUNNING, SERVICE_ACCEPT_STOP);
        if let Some(path) = path {
            run_policy_loop(path);
        }
        set_status(handle, SERVICE_STOPPED, 0);
    }

    unsafe extern "system" fn control_handler(control: u32) {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            STOP.store(true, Ordering::SeqCst);
        }
    }

    fn set_status(
        handle: SERVICE_STATUS_HANDLE,
        state: SERVICE_STATUS_CURRENT_STATE,
        accepted: u32,
    ) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 5_000,
        };
        let _ = unsafe { SetServiceStatus(handle, &status) };
    }

    fn run_policy_loop(path: PathBuf) {
        let mut engine = PolicyEngine::open().ok();
        let mut last_modified = None;
        while !STOP.load(Ordering::SeqCst) {
            let modified = std::fs::metadata(&path)
                .and_then(|metadata| metadata.modified())
                .ok();
            if modified != last_modified {
                last_modified = modified;
                if let Some(engine) = engine.as_mut() {
                    if let Ok(state) = load_state(&path) {
                        let _ = engine.apply(&state);
                    }
                } else {
                    engine = PolicyEngine::open().ok();
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
        if let Some(mut engine) = engine {
            engine.clear();
        }
    }

    struct PolicyEngine {
        engine: HANDLE,
        filter_ids: Vec<u64>,
    }

    impl PolicyEngine {
        fn open() -> Result<Self, String> {
            unsafe {
                let mut engine = HANDLE::default();
                let mut session = FWPM_SESSION0::default();
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
                let err =
                    FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine);
                if err != ERROR_SUCCESS.0 {
                    return Err(format!("FwpmEngineOpen0 failed: {err}"));
                }
                let mut sublayer = FWPM_SUBLAYER0::default();
                sublayer.subLayerKey = SUBLAYER_KEY;
                let name = windows::core::w!("m0untain service policy");
                sublayer.displayData.name = PWSTR(name.as_ptr() as *mut _);
                sublayer.weight = 0x9000;
                let err = FwpmSubLayerAdd0(engine, &sublayer, None);
                if err != ERROR_SUCCESS.0 {
                    let _ = FwpmEngineClose0(engine);
                    return Err(format!("FwpmSubLayerAdd0 failed: {err}"));
                }
                Ok(Self {
                    engine,
                    filter_ids: Vec::new(),
                })
            }
        }

        fn clear(&mut self) {
            unsafe {
                for id in self.filter_ids.drain(..) {
                    let _ = FwpmFilterDeleteById0(self.engine, id);
                }
            }
        }

        fn apply(&mut self, state: &PersistentState) -> Result<(), String> {
            self.clear();
            let now = now_ms();
            let active_profile_id = if state.settings.active_profile_id.is_empty() {
                "home"
            } else {
                state.settings.active_profile_id.as_str()
            };

            for rule in state.rules.values() {
                if !rule_is_active(rule, now)
                    || !rule_in_active_scope(rule, active_profile_id)
                    || !rule.direction_matches_outbound()
                {
                    continue;
                }
                match rule.decision.as_str() {
                    "allow" => self.add_rule_filters(rule, FWP_ACTION_PERMIT, 14)?,
                    "block" | "quarantine" => self.add_rule_filters(rule, FWP_ACTION_BLOCK, 15)?,
                    _ => {}
                }
            }

            if default_deny_enabled(state) {
                self.add_default_deny(FWPM_LAYER_ALE_AUTH_CONNECT_V4)?;
                self.add_default_deny(FWPM_LAYER_ALE_AUTH_CONNECT_V6)?;
            }
            Ok(())
        }

        fn add_default_deny(&mut self, layer: GUID) -> Result<(), String> {
            unsafe {
                let mut filter = FWPM_FILTER0::default();
                filter.layerKey = layer;
                filter.subLayerKey = SUBLAYER_KEY;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = 1;
                filter.action.r#type = FWP_ACTION_BLOCK;
                let name = windows::core::w!("m0untain default deny outbound");
                filter.displayData.name = PWSTR(name.as_ptr() as *mut _);
                let mut id = 0;
                let err = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut id));
                if err != ERROR_SUCCESS.0 {
                    return Err(format!("FwpmFilterAdd0(default deny) failed: {err}"));
                }
                self.filter_ids.push(id);
            }
            Ok(())
        }

        fn add_rule_filters(
            &mut self,
            rule: &ProgramRule,
            action: FWP_ACTION_TYPE,
            weight: u8,
        ) -> Result<(), String> {
            if rule.app_id.is_empty() && rule.app_path.is_empty() {
                return Ok(());
            }
            let app_id = if !rule.app_id.is_empty() {
                rule.app_id.clone()
            } else {
                app_id_from_path(&rule.app_path).unwrap_or_default()
            };
            if app_id.is_empty() {
                return Ok(());
            }
            let remote = remote_match_from_target(&rule.target)?;
            let port = rule.target.as_ref().and_then(|target| target.port);
            for layer in [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ] {
                if !target_matches_layer(remote, layer) {
                    continue;
                }
                if let Some(id) = unsafe {
                    add_app_filter(
                        self.engine,
                        &app_id,
                        layer,
                        rule,
                        remote,
                        port,
                        action,
                        weight,
                    )?
                } {
                    self.filter_ids.push(id);
                }
            }
            Ok(())
        }
    }

    impl Drop for PolicyEngine {
        fn drop(&mut self) {
            self.clear();
            unsafe {
                let _ = FwpmEngineClose0(self.engine);
            }
        }
    }

    trait RuleExt {
        fn direction_matches_outbound(&self) -> bool;
    }

    impl RuleExt for ProgramRule {
        fn direction_matches_outbound(&self) -> bool {
            self.direction.is_empty() || self.direction == "outbound" || self.direction == "both"
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum RemoteMatch {
        Ip(IpAddr),
        Cidr { network: IpAddr, prefix: u8 },
    }

    fn remote_match_from_target(
        target: &Option<RuleTarget>,
    ) -> Result<Option<RemoteMatch>, String> {
        let Some(target) = target else {
            return Ok(None);
        };
        match target.kind.to_lowercase().as_str() {
            "any" => Ok(None),
            "ip" => target
                .value
                .parse::<IpAddr>()
                .map(RemoteMatch::Ip)
                .map(Some)
                .map_err(|_| "invalid target IP".to_string()),
            "cidr" => {
                let Some((network, prefix)) = target.value.split_once('/') else {
                    return Err("invalid CIDR target".to_string());
                };
                let network = network
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid CIDR network".to_string())?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|_| "invalid CIDR prefix".to_string())?;
                Ok(Some(RemoteMatch::Cidr { network, prefix }))
            }
            // Domain rules need DNS/IP proof from the UI-side DNS mapper before
            // this service can safely convert them into WFP conditions.
            "domain" => Ok(None),
            _ => Ok(None),
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

    unsafe fn add_app_filter(
        engine: HANDLE,
        app_id: &[u8],
        layer: GUID,
        rule: &ProgramRule,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
        action: FWP_ACTION_TYPE,
        weight: u8,
    ) -> Result<Option<u64>, String> {
        if !target_matches_layer(remote, layer) {
            return Ok(None);
        }
        let mut blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_ptr() as *mut u8,
        };
        let mut conditions = Vec::with_capacity(4);
        let mut v6_storage: FWP_BYTE_ARRAY16;
        let mut v4_mask_storage: FWP_V4_ADDR_AND_MASK;
        let mut v6_mask_storage: FWP_V6_ADDR_AND_MASK;

        let mut app_condition = FWPM_FILTER_CONDITION0::default();
        app_condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        app_condition.matchType = FWP_MATCH_EQUAL;
        app_condition.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        app_condition.conditionValue.Anonymous.byteBlob = &mut blob;
        conditions.push(app_condition);

        match rule.protocol.as_str() {
            "tcp" | "udp" => {
                let mut condition = FWPM_FILTER_CONDITION0::default();
                condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                condition.matchType = FWP_MATCH_EQUAL;
                condition.conditionValue.r#type = FWP_UINT8;
                condition.conditionValue.Anonymous.uint8 =
                    if rule.protocol == "tcp" { 6 } else { 17 };
                conditions.push(condition);
            }
            _ => {}
        }

        if let Some(remote) = remote {
            let mut condition = FWPM_FILTER_CONDITION0::default();
            condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            condition.matchType = FWP_MATCH_EQUAL;
            match remote {
                RemoteMatch::Ip(IpAddr::V4(ip)) => {
                    condition.conditionValue.r#type = FWP_UINT32;
                    condition.conditionValue.Anonymous.uint32 = u32::from_be_bytes(ip.octets());
                }
                RemoteMatch::Ip(IpAddr::V6(ip)) => {
                    condition.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    v6_storage = FWP_BYTE_ARRAY16 {
                        byteArray16: ip.octets(),
                    };
                    condition.conditionValue.Anonymous.byteArray16 = &mut v6_storage;
                }
                RemoteMatch::Cidr {
                    network: IpAddr::V4(network),
                    prefix,
                } => {
                    condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
                    v4_mask_storage = FWP_V4_ADDR_AND_MASK {
                        addr: u32::from_be_bytes(network.octets()),
                        mask: ipv4_prefix_mask(prefix),
                    };
                    condition.conditionValue.Anonymous.v4AddrMask = &mut v4_mask_storage;
                }
                RemoteMatch::Cidr {
                    network: IpAddr::V6(network),
                    prefix,
                } => {
                    condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
                    v6_mask_storage = FWP_V6_ADDR_AND_MASK {
                        addr: network.octets(),
                        prefixLength: prefix,
                    };
                    condition.conditionValue.Anonymous.v6AddrMask = &mut v6_mask_storage;
                }
            }
            conditions.push(condition);
        }

        if let Some(port) = remote_port {
            let mut condition = FWPM_FILTER_CONDITION0::default();
            condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            condition.matchType = FWP_MATCH_EQUAL;
            condition.conditionValue.r#type = FWP_UINT16;
            condition.conditionValue.Anonymous.uint16 = port;
            conditions.push(condition);
        }

        let mut filter = FWPM_FILTER0::default();
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.r#type = action;
        let name = windows::core::w!("m0untain service app policy");
        filter.displayData.name = PWSTR(name.as_ptr() as *mut _);
        let mut id = 0;
        let err = FwpmFilterAdd0(engine, &filter, None, Some(&mut id));
        if err != ERROR_SUCCESS.0 {
            return Err(format!("FwpmFilterAdd0(service app policy) failed: {err}"));
        }
        Ok(Some(id))
    }

    fn app_id_from_path(path: &str) -> Option<Vec<u8>> {
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

    fn ipv4_prefix_mask(prefix: u8) -> u32 {
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix.min(32))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deny_can_be_enabled_by_active_profile() {
        let state = PersistentState {
            settings: AppSettings {
                active_profile_id: "lockdown".to_string(),
                default_deny_enabled: false,
            },
            profiles: vec![RuleProfile {
                id: "lockdown".to_string(),
                default_deny: true,
            }],
            ..PersistentState::default()
        };

        assert!(default_deny_enabled(&state));
    }

    #[test]
    fn expired_rules_are_not_active() {
        let mut rule = ProgramRule {
            expires_at_ms: Some(now_ms().saturating_sub(1)),
            ..ProgramRule::default()
        };
        assert!(!rule_is_active(&rule, now_ms()));
        rule.expires_at_ms = None;
        assert!(rule_is_active(&rule, now_ms()));
    }
}
