//! The detection engine ties the individual detectors together, tracks active
//! temporary blocks, honours a whitelist, and produces a single `Verdict` per
//! event. This is the brain the Tauri/WFP layer will drive.

pub mod ratelimit;
pub mod scan;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::event::NetEvent;
use ratelimit::RateLimiter;
use scan::ScanDetector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    RateLimit,
    PortScan,
    Manual,
    Blocklist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Block { until_ms: u64, reason: BlockReason },
}

impl Verdict {
    pub fn is_block(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
}

#[derive(Debug, Clone, Copy)]
struct BlockEntry {
    until_ms: u64,
    reason: BlockReason,
}

pub struct Engine {
    cfg: Config,
    rl: RateLimiter,
    scan: ScanDetector,
    blocked: HashMap<IpAddr, BlockEntry>,
    whitelist: HashSet<IpAddr>,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        Engine {
            rl: RateLimiter::new(cfg.ddos.clone()),
            scan: ScanDetector::new(cfg.scan.clone()),
            cfg,
            blocked: HashMap::new(),
            whitelist: HashSet::new(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Replace the whole config at runtime (e.g. user edited settings).
    pub fn set_config(&mut self, cfg: Config) {
        self.rl.set_config(cfg.ddos.clone());
        self.scan.set_config(cfg.scan.clone());
        self.cfg = cfg;
    }

    pub fn set_ddos_enabled(&mut self, on: bool) {
        self.cfg.ddos.enabled = on;
        self.rl.set_config(self.cfg.ddos.clone());
    }

    pub fn set_scan_enabled(&mut self, on: bool) {
        self.cfg.scan.enabled = on;
        self.scan.set_config(self.cfg.scan.clone());
    }

    pub fn whitelist_add(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
    }

    pub fn whitelist_remove(&mut self, ip: &IpAddr) {
        self.whitelist.remove(ip);
    }

    /// Manually block an IP until `until_ms`.
    pub fn block_manual(&mut self, ip: IpAddr, until_ms: u64) {
        self.blocked.insert(
            ip,
            BlockEntry {
                until_ms,
                reason: BlockReason::Manual,
            },
        );
    }

    pub fn unblock(&mut self, ip: &IpAddr) {
        self.blocked.remove(ip);
    }

    /// Snapshot of currently-active blocks (for the UI block list).
    pub fn active_blocks(&self, now: u64) -> Vec<(IpAddr, u64, BlockReason)> {
        self.blocked
            .iter()
            .filter(|(_, b)| now < b.until_ms)
            .map(|(ip, b)| (*ip, b.until_ms, b.reason))
            .collect()
    }

    /// The core call: inspect one event and decide.
    pub fn inspect(&mut self, ev: &NetEvent) -> Verdict {
        // Trusted sources always pass.
        if self.whitelist.contains(&ev.remote_ip) {
            return Verdict::Pass;
        }

        // Already under an active temporary block?
        if let Some(b) = self.blocked.get(&ev.remote_ip) {
            if ev.ts_ms < b.until_ms {
                return Verdict::Block {
                    until_ms: b.until_ms,
                    reason: b.reason,
                };
            }
        }

        // Flood check.
        if self.rl.check(ev) {
            let until = ev.ts_ms + self.cfg.ddos.block_ms;
            self.blocked.insert(
                ev.remote_ip,
                BlockEntry {
                    until_ms: until,
                    reason: BlockReason::RateLimit,
                },
            );
            return Verdict::Block {
                until_ms: until,
                reason: BlockReason::RateLimit,
            };
        }

        // Scan check.
        if self.scan.check(ev) {
            let until = ev.ts_ms + self.cfg.scan.block_ms;
            self.blocked.insert(
                ev.remote_ip,
                BlockEntry {
                    until_ms: until,
                    reason: BlockReason::PortScan,
                },
            );
            return Verdict::Block {
                until_ms: until,
                reason: BlockReason::PortScan,
            };
        }

        Verdict::Pass
    }

    /// Housekeeping: expire old blocks and prune detector state. Call this on a
    /// timer (e.g. once a second) from the host layer.
    pub fn tick(&mut self, now: u64) {
        self.blocked.retain(|_, b| now < b.until_ms);
        self.rl.cleanup(now);
        self.scan.cleanup(now);
    }
}
