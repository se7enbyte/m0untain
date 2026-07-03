//! Runtime configuration. Everything the user can toggle or tune lives here.
//! Serde-serialisable so the Tauri layer can persist it to disk and the UI can
//! round-trip it as JSON.

use serde::{Deserialize, Serialize};

/// DDoS / flood protection (inbound). Host-based: protects THIS machine's
/// resources against connection/SYN floods and lets you shed load. It cannot
/// stop volumetric attacks that saturate your uplink — that is an ISP/network
/// problem no local software can fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdosConfig {
    pub enabled: bool,
    /// Sliding window length in milliseconds.
    pub window_ms: u64,
    /// Max NEW inbound connections a single source IP may open per window
    /// before it is temporarily blocked.
    pub max_conns_per_window: u32,
    /// How long (ms) to keep a tripped IP blocked.
    pub block_ms: u64,
    /// Optional global cap across ALL source IPs per window (0 = disabled).
    /// A crude but effective total-inbound rate limit for load shedding.
    pub global_max_conns_per_window: u32,
}

impl Default for DdosConfig {
    fn default() -> Self {
        DdosConfig {
            enabled: true,
            window_ms: 1_000,
            max_conns_per_window: 40,
            block_ms: 60_000,
            global_max_conns_per_window: 0,
        }
    }
}

/// Port-scan / IP-reconnaissance protection (inbound). Trips when a single
/// source touches too many distinct local ports inside a short window — the
/// signature of a horizontal/vertical port sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    pub enabled: bool,
    pub window_ms: u64,
    /// Distinct local ports from one source within the window that flags a scan.
    pub distinct_ports_threshold: u32,
    pub block_ms: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            enabled: true,
            window_ms: 3_000,
            distinct_ports_threshold: 15,
            block_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Config {
    pub ddos: DdosConfig,
    pub scan: ScanConfig,
}

impl Config {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
    pub fn from_json(s: &str) -> Result<Config, serde_json::Error> {
        serde_json::from_str(s)
    }
}
