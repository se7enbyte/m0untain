use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct AppSettings {
    pub launch_on_startup: bool,
    pub close_to_tray: bool,
    pub ask_new_apps: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            launch_on_startup: false,
            close_to_tray: true,
            ask_new_apps: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramRule {
    pub app_path: String,
    pub app_name: String,
    pub app_id: Vec<u8>,
    /// "allow" or "quarantine".
    pub decision: String,
    /// "all", "tcp" or "udp".
    pub protocol: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistentState {
    #[serde(default)]
    pub settings: AppSettings,
    #[serde(default)]
    pub rules: HashMap<String, ProgramRule>,
}

pub fn load(path: &Path) -> PersistentState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
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
