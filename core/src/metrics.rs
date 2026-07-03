//! Rolling, bucketed time-series that feeds the dashboard line charts. Each
//! bucket is a fixed slice of wall-clock time (default 1s). The ring keeps the
//! last `capacity` buckets so the UI can draw a live scrolling window.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::Serialize;

use crate::detect::{BlockReason, Verdict};
use crate::event::{Direction, NetEvent};

/// A finalised bucket as sent to the UI (no internal sets).
#[derive(Debug, Clone, Serialize, Default)]
pub struct BucketOut {
    pub t_ms: u64,
    pub events: u32,
    pub inbound: u32,
    pub outbound: u32,
    pub passed: u32,
    pub blocked: u32,
    pub ratelimit_blocks: u32,
    pub scan_blocks: u32,
    pub unique_ips: u32,
}

#[derive(Debug, Clone, Default)]
struct Bucket {
    t_ms: u64,
    events: u32,
    inbound: u32,
    outbound: u32,
    passed: u32,
    blocked: u32,
    ratelimit_blocks: u32,
    scan_blocks: u32,
    ips: HashSet<IpAddr>,
}

impl Bucket {
    fn finalize(&self) -> BucketOut {
        BucketOut {
            t_ms: self.t_ms,
            events: self.events,
            inbound: self.inbound,
            outbound: self.outbound,
            passed: self.passed,
            blocked: self.blocked,
            ratelimit_blocks: self.ratelimit_blocks,
            scan_blocks: self.scan_blocks,
            unique_ips: self.ips.len() as u32,
        }
    }
}

pub struct Metrics {
    bucket_ms: u64,
    capacity: usize,
    buckets: Vec<Bucket>, // ordered oldest -> newest
}

impl Metrics {
    pub fn new(bucket_ms: u64, capacity: usize) -> Self {
        Metrics {
            bucket_ms: bucket_ms.max(1),
            capacity: capacity.max(1),
            buckets: Vec::new(),
        }
    }

    fn bucket_start(&self, ts_ms: u64) -> u64 {
        ts_ms - (ts_ms % self.bucket_ms)
    }

    fn current_mut(&mut self, ts_ms: u64) -> &mut Bucket {
        let start = self.bucket_start(ts_ms);
        match self.buckets.last() {
            Some(b) if b.t_ms == start => {}
            _ => {
                self.buckets.push(Bucket {
                    t_ms: start,
                    ..Default::default()
                });
                if self.buckets.len() > self.capacity {
                    let overflow = self.buckets.len() - self.capacity;
                    self.buckets.drain(0..overflow);
                }
            }
        }
        self.buckets.last_mut().unwrap()
    }

    pub fn record(&mut self, ev: &NetEvent, verdict: &Verdict) {
        let ip = ev.remote_ip;
        let dir = ev.direction;
        let b = self.current_mut(ev.ts_ms);
        b.events += 1;
        b.ips.insert(ip);
        match dir {
            Direction::Inbound => b.inbound += 1,
            Direction::Outbound => b.outbound += 1,
        }
        match verdict {
            Verdict::Pass => b.passed += 1,
            Verdict::Block { reason, .. } => {
                b.blocked += 1;
                match reason {
                    BlockReason::RateLimit => b.ratelimit_blocks += 1,
                    BlockReason::PortScan => b.scan_blocks += 1,
                    _ => {}
                }
            }
        }
    }

    /// Snapshot for the charts, oldest bucket first.
    pub fn series(&self) -> Vec<BucketOut> {
        self.buckets.iter().map(|b| b.finalize()).collect()
    }

    pub fn latest(&self) -> Option<BucketOut> {
        self.buckets.last().map(|b| b.finalize())
    }
}
