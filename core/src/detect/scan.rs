//! Port-scan / IP-reconnaissance detector.
//!
//! Signature: a single source IP touching many DISTINCT local ports within a
//! short window. Hammering one port looks like a flood (that is the rate
//! limiter's job); fanning out across many ports looks like a sweep.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use crate::config::ScanConfig;
use crate::event::{Direction, NetEvent};

pub struct ScanDetector {
    cfg: ScanConfig,
    // per source IP: recent (timestamp, probed_local_port) pairs
    per_ip: HashMap<IpAddr, VecDeque<(u64, u16)>>,
}

impl ScanDetector {
    pub fn new(cfg: ScanConfig) -> Self {
        ScanDetector {
            cfg,
            per_ip: HashMap::new(),
        }
    }

    pub fn set_config(&mut self, cfg: ScanConfig) {
        self.cfg = cfg;
    }

    /// Records the event and returns `true` if this source now looks like a scan.
    pub fn check(&mut self, ev: &NetEvent) -> bool {
        if !self.cfg.enabled {
            return false;
        }
        if ev.direction != Direction::Inbound || !ev.is_new_conn {
            return false;
        }

        let now = ev.ts_ms;
        let window = self.cfg.window_ms;

        let dq = self.per_ip.entry(ev.remote_ip).or_default();
        dq.push_back((now, ev.local_port));
        while let Some(&(ts, _)) = dq.front() {
            if now.saturating_sub(ts) > window {
                dq.pop_front();
            } else {
                break;
            }
        }

        let distinct: HashSet<u16> = dq.iter().map(|&(_, p)| p).collect();
        distinct.len() as u32 > self.cfg.distinct_ports_threshold
    }

    pub fn cleanup(&mut self, now: u64) {
        let window = self.cfg.window_ms;
        self.per_ip.retain(|_, dq| {
            while let Some(&(ts, _)) = dq.front() {
                if now.saturating_sub(ts) > window {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
    }
}
