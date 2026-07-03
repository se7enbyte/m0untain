//! DDoS / flood detector: per-source-IP sliding-window rate limiting, plus an
//! optional global cap for load shedding.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::config::DdosConfig;
use crate::event::{Direction, NetEvent};

pub struct RateLimiter {
    cfg: DdosConfig,
    per_ip: HashMap<IpAddr, VecDeque<u64>>,
    global: VecDeque<u64>,
}

impl RateLimiter {
    pub fn new(cfg: DdosConfig) -> Self {
        RateLimiter {
            cfg,
            per_ip: HashMap::new(),
            global: VecDeque::new(),
        }
    }

    pub fn set_config(&mut self, cfg: DdosConfig) {
        self.cfg = cfg;
    }

    fn trim(dq: &mut VecDeque<u64>, now: u64, window: u64) {
        while let Some(&front) = dq.front() {
            if now.saturating_sub(front) > window {
                dq.pop_front();
            } else {
                break;
            }
        }
    }

    /// Records the event and returns `true` if it trips the DDoS threshold.
    pub fn check(&mut self, ev: &NetEvent) -> bool {
        if !self.cfg.enabled {
            return false;
        }
        // Only new inbound connection attempts count toward a flood.
        if ev.direction != Direction::Inbound || !ev.is_new_conn {
            return false;
        }

        let now = ev.ts_ms;
        let window = self.cfg.window_ms;

        let dq = self.per_ip.entry(ev.remote_ip).or_default();
        dq.push_back(now);
        Self::trim(dq, now, window);
        let per_ip_trip = dq.len() as u32 > self.cfg.max_conns_per_window;

        let mut global_trip = false;
        if self.cfg.global_max_conns_per_window > 0 {
            self.global.push_back(now);
            Self::trim(&mut self.global, now, window);
            global_trip = self.global.len() as u32 > self.cfg.global_max_conns_per_window;
        }

        per_ip_trip || global_trip
    }

    /// Periodic housekeeping: drop IPs with no recent activity so memory does
    /// not grow unbounded under a spoofed-source flood.
    pub fn cleanup(&mut self, now: u64) {
        let window = self.cfg.window_ms;
        self.per_ip.retain(|_, dq| {
            Self::trim(dq, now, window);
            !dq.is_empty()
        });
        Self::trim(&mut self.global, now, window);
    }

    pub fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }
}
