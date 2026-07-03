use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const GLOBAL_PROFILE_ID: &str = "global";
pub const DEFAULT_PROFILE_ID: &str = "home";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct AppSettings {
    pub launch_on_startup: bool,
    pub close_to_tray: bool,
    pub ask_new_apps: bool,
    pub active_profile_id: String,
    pub default_deny_enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            launch_on_startup: false,
            close_to_tray: true,
            ask_new_apps: true,
            active_profile_id: DEFAULT_PROFILE_ID.to_string(),
            default_deny_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct RuleTarget {
    /// "any", "ip", "domain" or "cidr".
    pub kind: String,
    pub value: String,
    pub port: Option<u16>,
}

impl Default for RuleTarget {
    fn default() -> Self {
        Self {
            kind: "any".to_string(),
            value: String::new(),
            port: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct ProgramRule {
    pub app_path: String,
    pub app_name: String,
    pub app_id: Vec<u8>,
    pub app_package_sid: Vec<u8>,
    /// "allow", "block" or "quarantine".
    pub decision: String,
    /// "all", "tcp" or "udp".
    pub protocol: String,
    /// "inbound", "outbound" or "both".
    pub direction: String,
    pub target: Option<RuleTarget>,
    pub expires_at_ms: Option<u64>,
    pub profile_id: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl Default for ProgramRule {
    fn default() -> Self {
        Self {
            app_path: String::new(),
            app_name: String::new(),
            app_id: Vec::new(),
            app_package_sid: Vec::new(),
            decision: "allow".to_string(),
            protocol: "all".to_string(),
            direction: "outbound".to_string(),
            target: None,
            expires_at_ms: None,
            profile_id: GLOBAL_PROFILE_ID.to_string(),
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }
}

impl ProgramRule {
    pub fn is_blocking(&self) -> bool {
        self.decision == "block" || self.decision == "quarantine"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct RuleProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_deny: bool,
}

impl Default for RuleProfile {
    fn default() -> Self {
        Self {
            id: DEFAULT_PROFILE_ID.to_string(),
            name: "Home".to_string(),
            description: "Trusted personal network".to_string(),
            default_deny: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct NotificationRecord {
    pub id: String,
    pub ts_ms: u64,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub app_path: Option<String>,
    pub remote: Option<String>,
}

impl Default for NotificationRecord {
    fn default() -> Self {
        Self {
            id: String::new(),
            ts_ms: 0,
            kind: "info".to_string(),
            title: String::new(),
            body: String::new(),
            app_path: None,
            remote: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentState {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub rules: HashMap<String, ProgramRule>,
    #[serde(default = "default_profiles")]
    pub profiles: Vec<RuleProfile>,
    #[serde(default)]
    pub notifications: Vec<NotificationRecord>,
}

fn schema_version() -> u32 {
    2
}

pub fn default_profiles() -> Vec<RuleProfile> {
    vec![
        RuleProfile {
            id: "home".to_string(),
            name: "Home".to_string(),
            description: "Trusted personal network".to_string(),
            default_deny: false,
        },
        RuleProfile {
            id: "public-wifi".to_string(),
            name: "Public Wi-Fi".to_string(),
            description: "Ask more, trust less".to_string(),
            default_deny: true,
        },
        RuleProfile {
            id: "gaming".to_string(),
            name: "Gaming".to_string(),
            description: "Low-friction mode for known apps".to_string(),
            default_deny: false,
        },
        RuleProfile {
            id: "work".to_string(),
            name: "Work".to_string(),
            description: "Productivity and VPN friendly".to_string(),
            default_deny: false,
        },
        RuleProfile {
            id: "lockdown".to_string(),
            name: "Lockdown".to_string(),
            description: "Default deny for unknown outbound traffic".to_string(),
            default_deny: true,
        },
    ]
}

pub fn normalize_state(mut state: PersistentState) -> PersistentState {
    state.schema_version = 2;
    if state.profiles.is_empty() {
        state.profiles = default_profiles();
    }
    if !state
        .profiles
        .iter()
        .any(|profile| profile.id == state.settings.active_profile_id)
    {
        state.settings.active_profile_id = DEFAULT_PROFILE_ID.to_string();
    }
    for rule in state.rules.values_mut() {
        if rule.profile_id.is_empty() {
            rule.profile_id = GLOBAL_PROFILE_ID.to_string();
        }
        if rule.protocol.is_empty() {
            rule.protocol = "all".to_string();
        }
        if rule.direction.is_empty() {
            rule.direction = "outbound".to_string();
        }
        if rule.decision == "quarantine" || rule.decision == "block" || rule.decision == "allow" {
            // already valid enough for older state files
        } else {
            rule.decision = "allow".to_string();
        }
    }
    if state.notifications.len() > 400 {
        let keep_from = state.notifications.len() - 400;
        state.notifications = state.notifications.split_off(keep_from);
    }
    state
}

pub fn load(path: &Path) -> PersistentState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .map(normalize_state)
        .unwrap_or_else(|| normalize_state(PersistentState::default()))
}

pub fn save(path: &Path, state: &PersistentState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    std::fs::write(path, json).map_err(|error| error.to_string())
}

pub fn default_path(config_dir: PathBuf) -> PathBuf {
    config_dir.join("state.json")
}

#[cfg(windows)]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    use windows::core::w;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_SET_VALUE, REG_SZ,
    };

    unsafe {
        let mut key = HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            0,
            KEY_SET_VALUE,
            &mut key,
        );
        if result != ERROR_SUCCESS {
            return Err(format!(
                "Windows startup key could not be opened: {}",
                result.0
            ));
        }

        let operation = if enabled {
            let exe = std::env::current_exe().map_err(|error| error.to_string())?;
            let command = format!("\"{}\" --hidden", exe.display());
            let wide: Vec<u16> = std::ffi::OsStr::new(&command)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let bytes = std::slice::from_raw_parts(
                wide.as_ptr() as *const u8,
                wide.len() * std::mem::size_of::<u16>(),
            );
            RegSetValueExW(key, w!("m0untain"), 0, REG_SZ, Some(bytes))
        } else {
            RegDeleteValueW(key, w!("m0untain"))
        };
        let _ = RegCloseKey(key);

        if operation != ERROR_SUCCESS && operation != ERROR_FILE_NOT_FOUND {
            return Err(format!("Windows startup setting failed: {}", operation.0));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn set_autostart(_enabled: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_v1_rules_into_v2_defaults() {
        let json = r#"{
            "settings": { "askNewApps": true },
            "rules": {
                "c:\\tools\\demo.exe": {
                    "appPath": "C:\\tools\\demo.exe",
                    "appName": "demo.exe",
                    "decision": "allow",
                    "protocol": "tcp"
                }
            }
        }"#;

        let state = normalize_state(serde_json::from_str(json).unwrap());
        let rule = state.rules.get("c:\\tools\\demo.exe").unwrap();

        assert_eq!(state.schema_version, 2);
        assert_eq!(state.settings.active_profile_id, DEFAULT_PROFILE_ID);
        assert_eq!(rule.profile_id, GLOBAL_PROFILE_ID);
        assert_eq!(rule.direction, "outbound");
        assert_eq!(state.profiles.len(), 5);
    }

    #[test]
    fn trims_notification_history_to_recent_records() {
        let mut state = PersistentState::default();
        state.notifications = (0..450)
            .map(|idx| NotificationRecord {
                id: idx.to_string(),
                ts_ms: idx,
                ..NotificationRecord::default()
            })
            .collect();

        let state = normalize_state(state);

        assert_eq!(state.notifications.len(), 400);
        assert_eq!(state.notifications.first().unwrap().id, "50");
    }

    #[test]
    fn state_json_roundtrips_v2_schema() {
        let mut state = normalize_state(PersistentState::default());
        state.rules.insert(
            "home|demo|tcp|outbound|any".to_string(),
            ProgramRule {
                app_path: "C:\\demo.exe".to_string(),
                app_name: "demo.exe".to_string(),
                decision: "allow".to_string(),
                protocol: "tcp".to_string(),
                profile_id: "home".to_string(),
                ..ProgramRule::default()
            },
        );

        let json = serde_json::to_string_pretty(&state).unwrap();
        let decoded = normalize_state(serde_json::from_str(&json).unwrap());

        assert_eq!(decoded.schema_version, 2);
        assert_eq!(decoded.rules.len(), 1);
        assert_eq!(decoded.profiles.len(), 5);
        assert_eq!(decoded.settings.active_profile_id, "home");
    }
}
