//! The aggregation pipeline that turns raw engine/metrics state into the exact
//! per-second payload the dashboard consumes. Platform-independent, so it is
//! unit-tested here rather than inside the Tauri glue.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use serde::Serialize;

use crate::detect::BlockReason;
use crate::metrics::BucketOut;

/// Rolling top-talkers tracker: counts events per source IP within a window.
pub struct Talkers {
    window_ms: u64,
    hits: HashMap<IpAddr, VecDeque<u64>>,
}

impl Talkers {
    pub fn new(window_ms: u64) -> Self {
        Talkers {
            window_ms: window_ms.max(1),
            hits: HashMap::new(),
        }
    }

    pub fn record(&mut self, ip: IpAddr, ts_ms: u64) {
        let dq = self.hits.entry(ip).or_default();
        dq.push_back(ts_ms);
        let w = self.window_ms;
        while let Some(&f) = dq.front() {
            if ts_ms.saturating_sub(f) > w {
                dq.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn cleanup(&mut self, now: u64) {
        let w = self.window_ms;
        self.hits.retain(|_, dq| {
            while let Some(&f) = dq.front() {
                if now.saturating_sub(f) > w {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            !dq.is_empty()
        });
    }

    /// Top `n` sources by volume. `flagged` marks IPs currently blocked.
    pub fn top(&self, n: usize, flagged: &[IpAddr]) -> Vec<TalkerOut> {
        let mut v: Vec<TalkerOut> = self
            .hits
            .iter()
            .map(|(ip, dq)| TalkerOut {
                ip: ip.to_string(),
                n: dq.len() as u32,
                flag: flagged.contains(ip),
            })
            .collect();
        v.sort_by_key(|entry| std::cmp::Reverse(entry.n));
        v.truncate(n);
        v
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TalkerOut {
    pub ip: String,
    pub n: u32,
    pub flag: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BlockOut {
    pub ip: String,
    pub reason: String,
    pub ttl: u64,
}

/// The exact shape emitted as the `metrics-tick` event and consumed by
/// `applyTick` in the dashboard.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TickPayload {
    pub inbound: u32,
    pub outbound: u32,
    pub flood: u32,
    pub scan: u32,
    pub unique: u32,
    pub drop: u32, // percentage 0..100
    pub blocks: Vec<BlockOut>,
    pub talkers: Vec<TalkerOut>,
}

fn reason_str(r: BlockReason) -> &'static str {
    match r {
        BlockReason::RateLimit => "flood",
        BlockReason::PortScan => "scan",
        BlockReason::Manual => "manual",
        BlockReason::Blocklist => "blocklist",
    }
}

/// Build one tick from the latest metrics bucket, the active-block list, and the
/// talkers tracker.
pub fn build_tick(
    bucket: Option<&BucketOut>,
    active_blocks: &[(IpAddr, u64, BlockReason)],
    talkers: &Talkers,
    now_ms: u64,
) -> TickPayload {
    let b = bucket.cloned().unwrap_or_default();
    let total = b.events.max(1);
    let drop = ((b.blocked as f64 / total as f64) * 100.0).round() as u32;

    let mut blocks: Vec<BlockOut> = active_blocks
        .iter()
        .map(|(ip, until, reason)| BlockOut {
            ip: ip.to_string(),
            reason: reason_str(*reason).to_string(),
            ttl: until.saturating_sub(now_ms) / 1000,
        })
        .collect();
    blocks.sort_by_key(|block| std::cmp::Reverse(block.ttl));

    let flagged: Vec<IpAddr> = active_blocks.iter().map(|(ip, _, _)| *ip).collect();

    TickPayload {
        inbound: b.inbound,
        outbound: b.outbound,
        flood: b.ratelimit_blocks,
        scan: b.scan_blocks,
        unique: b.unique_ips,
        drop: drop.min(100),
        blocks,
        talkers: talkers.top(7, &flagged),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    #[test]
    fn talkers_rank_and_flag() {
        let mut t = Talkers::new(60_000);
        for _ in 0..10 {
            t.record(ip(1), 1_000);
        }
        for _ in 0..3 {
            t.record(ip(2), 1_000);
        }
        let top = t.top(5, &[ip(1)]);
        assert_eq!(top[0].ip, ip(1).to_string());
        assert_eq!(top[0].n, 10);
        assert!(top[0].flag, "blocked IP should be flagged");
        assert_eq!(top[1].n, 3);
        assert!(!top[1].flag);
    }

    #[test]
    fn talkers_window_expires() {
        let mut t = Talkers::new(1_000);
        for i in 0..5 {
            t.record(ip(1), i * 100);
        }
        t.cleanup(5_000); // long after window
        assert!(t.top(5, &[]).is_empty(), "stale talkers pruned");
    }

    #[test]
    fn build_tick_shapes_payload() {
        let bucket = BucketOut {
            t_ms: 1_000,
            events: 100,
            inbound: 70,
            outbound: 30,
            passed: 90,
            blocked: 10,
            ratelimit_blocks: 6,
            scan_blocks: 4,
            unique_ips: 12,
        };
        let blocks = vec![
            (ip(1), 61_000u64, BlockReason::RateLimit),
            (ip(2), 301_000u64, BlockReason::PortScan),
        ];
        let mut talkers = Talkers::new(60_000);
        talkers.record(ip(1), 1_000);
        let p = build_tick(Some(&bucket), &blocks, &talkers, 1_000);
        assert_eq!(p.inbound, 70);
        assert_eq!(p.outbound, 30);
        assert_eq!(p.flood, 6);
        assert_eq!(p.scan, 4);
        assert_eq!(p.unique, 12);
        assert_eq!(p.drop, 10); // 10/100 = 10%
        assert_eq!(p.blocks.len(), 2);
        // scan block has the longer ttl so it sorts first
        assert_eq!(p.blocks[0].reason, "scan");
        assert_eq!(p.blocks[0].ttl, 300);
        assert_eq!(p.blocks[1].reason, "flood");
        assert_eq!(p.blocks[1].ttl, 60);
    }

    #[test]
    fn build_tick_handles_empty_bucket() {
        let talkers = Talkers::new(1_000);
        let p = build_tick(None, &[], &talkers, 0);
        assert_eq!(p.inbound, 0);
        assert_eq!(p.drop, 0);
        assert!(p.blocks.is_empty());
    }
}
