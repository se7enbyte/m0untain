//! m0untain service scaffold.
//!
//! V2 keeps the public contract for a boot-time/default-deny Windows service in
//! the workspace without enabling install/start UX yet. The Tauri app can show
//! service-offline/app-only protection now, while this crate becomes the place
//! for persistent WFP policy enforcement in the next staged pass.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceMode {
    AppOnly,
    InstalledStopped,
    RunningDefaultDeny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub fn current_status() -> ServiceStatus {
    ServiceStatus::app_only()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_status_is_app_only_until_service_install_exists() {
        let status = current_status();

        assert!(!status.installed);
        assert!(!status.running);
        assert_eq!(status.mode, ServiceMode::AppOnly);
    }
}
