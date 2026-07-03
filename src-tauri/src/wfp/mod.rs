//! Platform firewall abstraction.
//!
//! The rest of the app talks only to the [`Firewall`] trait and consumes
//! [`RawConn`] events over a channel. On Windows this is backed by the Windows
//! Filtering Platform; everywhere else (and for pipeline/UI testing) it is
//! backed by a synthetic traffic simulator. Both drive the identical detection
//! pipeline, so the only Windows-specific surface is this module.

use std::net::IpAddr;
use std::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy)]
pub enum AppProtocol {
    All,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy)]
pub enum RemoteMatch {
    Ip(IpAddr),
    Cidr { network: IpAddr, prefix: u8 },
}

/// A raw connection observation from the OS network stack, before it is turned
/// into a `sentinel_core::NetEvent`.
#[derive(Debug, Clone)]
pub struct RawConn {
    pub ts_ms: u64,
    pub inbound: bool,
    pub is_new: bool,
    pub udp: bool,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// Port on this host (the probed port for inbound traffic).
    pub local_port: u16,
    pub pid: u32,
    /// WFP application identifier bytes. Used to create an ALE_APP_ID rule.
    pub app_id: Option<Vec<u8>>,
    /// Human-readable path decoded from the WFP application identifier.
    pub app_path: Option<String>,
    /// Package/AppContainer SID bytes for packaged apps (MSIX/UWP/Store apps).
    pub app_package_sid: Option<Vec<u8>>,
    /// Stable SID string, used as a synthetic app path when Windows does not
    /// expose a normal executable path for a packaged app.
    pub app_package_sid_string: Option<String>,
    /// Best-effort display name derived from the package SID/account lookup.
    pub app_name: Option<String>,
}

/// Installs and removes temporary block filters. Implementations must be
/// cheap to clone-share across threads (wrap handles internally).
pub trait Firewall: Send + Sync + 'static {
    /// Install a BLOCK rule for `ip`. Returns an opaque handle used to remove it.
    fn block_ip(&self, ip: IpAddr) -> Result<u64, String>;
    /// Block future outbound connections for an application.
    fn block_app(&self, app_id: &[u8], protocol: AppProtocol) -> Result<u64, String>;
    /// Block future outbound connections for a packaged application.
    fn block_package(&self, package_sid: &[u8], protocol: AppProtocol) -> Result<u64, String>;
    /// Block future outbound connections for an app, optionally scoped to a
    /// remote IP/CIDR and/or remote port.
    fn block_app_target(
        &self,
        app_id: &[u8],
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<u64, String> {
        let _ = (remote, remote_port);
        self.block_app(app_id, protocol)
    }
    /// Block future outbound connections for a packaged app, optionally scoped
    /// to a remote IP/CIDR and/or remote port.
    fn block_package_target(
        &self,
        package_sid: &[u8],
        protocol: AppProtocol,
        remote: Option<RemoteMatch>,
        remote_port: Option<u16>,
    ) -> Result<u64, String> {
        let _ = (remote, remote_port);
        self.block_package(package_sid, protocol)
    }
    /// Remove a previously installed block.
    fn unblock(&self, handle: u64) -> Result<(), String>;
    /// Human-readable backend name for the UI ("WFP" or "Simulator").
    fn backend(&self) -> &'static str;
}

#[cfg(windows)]
mod windows_impl;
#[cfg(windows)]
pub use windows_impl::WfpFirewall as PlatformFirewall;

#[cfg(not(windows))]
mod sim;
#[cfg(not(windows))]
pub use sim::SimFirewall as PlatformFirewall;

/// Construct the platform firewall and start its event source. Raw connection
/// events are delivered on `tx`.
pub fn start(tx: Sender<RawConn>) -> Result<PlatformFirewall, String> {
    PlatformFirewall::start(tx)
}

#[cfg(windows)]
pub fn app_id_from_path(path: &str) -> Option<Vec<u8>> {
    windows_impl::app_id_from_path(path)
}

#[cfg(not(windows))]
pub fn app_id_from_path(_path: &str) -> Option<Vec<u8>> {
    None
}
