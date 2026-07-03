//! sentinel-core: platform-independent firewall brain.
//!
//! Contains the event model, user config, the detection engine (DDoS
//! rate-limiting + port-scan detection), and rolling dashboard metrics. It has
//! zero Windows/WFP dependencies so it builds and is fully unit-tested on any
//! platform. The Windows-only WFP plumbing lives in the `src-tauri` crate and
//! merely feeds `NetEvent`s into `Engine::inspect`.

pub mod config;
pub mod detect;
pub mod event;
pub mod metrics;
pub mod pipeline;

pub use config::{Config, DdosConfig, ScanConfig};
pub use detect::{BlockReason, Engine, Verdict};
pub use event::{Action, Direction, NetEvent, Proto};
pub use metrics::{BucketOut, Metrics};
pub use pipeline::{build_tick, BlockOut, TalkerOut, Talkers, TickPayload};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        // Small, obvious thresholds for deterministic tests.
        c.ddos = DdosConfig {
            enabled: true,
            window_ms: 1_000,
            max_conns_per_window: 5,
            block_ms: 10_000,
            global_max_conns_per_window: 0,
        };
        c.scan = ScanConfig {
            enabled: true,
            window_ms: 2_000,
            distinct_ports_threshold: 6,
            block_ms: 20_000,
        };
        c
    }

    // ---- DDoS rate limiter -------------------------------------------------

    #[test]
    fn ddos_trips_after_threshold_within_window() {
        let mut e = Engine::new(cfg());
        let attacker = ip(1);
        // 5 allowed (threshold is "> 5"), the 6th trips.
        for i in 0..5 {
            let ev = NetEvent::inbound_new(i * 10, Proto::Tcp, attacker, 80);
            assert_eq!(e.inspect(&ev), Verdict::Pass, "conn {i} should pass");
        }
        let ev = NetEvent::inbound_new(60, Proto::Tcp, attacker, 80);
        assert!(e.inspect(&ev).is_block(), "6th conn in window must block");
    }

    #[test]
    fn ddos_does_not_trip_when_spread_across_windows() {
        let mut e = Engine::new(cfg());
        let slow = ip(2);
        // One connection every 300ms => at most a few per 1000ms window, never > 5.
        for i in 0..30u64 {
            let ev = NetEvent::inbound_new(i * 300, Proto::Tcp, slow, 80);
            assert_eq!(e.inspect(&ev), Verdict::Pass, "slow conn {i} should pass");
        }
    }

    #[test]
    fn ddos_isolates_per_ip() {
        let mut e = Engine::new(cfg());
        // Attacker floods; a bystander hitting the same port stays clean.
        for i in 0..6 {
            let _ = e.inspect(&NetEvent::inbound_new(i, Proto::Tcp, ip(1), 80));
        }
        let bystander = NetEvent::inbound_new(7, Proto::Tcp, ip(9), 80);
        assert_eq!(e.inspect(&bystander), Verdict::Pass, "bystander unaffected");
    }

    #[test]
    fn ddos_block_expires_then_passes_again() {
        let mut e = Engine::new(cfg());
        let a = ip(1);
        for i in 0..6 {
            let _ = e.inspect(&NetEvent::inbound_new(i, Proto::Tcp, a, 80));
        }
        // Still blocked during the block window.
        assert!(e
            .inspect(&NetEvent::inbound_new(5_000, Proto::Tcp, a, 80))
            .is_block());
        // After block_ms (10s) has passed, housekeeping expires it and it passes.
        e.tick(20_000);
        assert_eq!(
            e.inspect(&NetEvent::inbound_new(20_001, Proto::Tcp, a, 80)),
            Verdict::Pass,
            "block should have expired"
        );
    }

    #[test]
    fn ddos_toggle_off_disables_blocking() {
        let mut e = Engine::new(cfg());
        e.set_ddos_enabled(false);
        for i in 0..50 {
            let ev = NetEvent::inbound_new(i, Proto::Tcp, ip(1), 80);
            assert_eq!(e.inspect(&ev), Verdict::Pass, "disabled => never blocks");
        }
    }

    #[test]
    fn ddos_ignores_outbound() {
        let mut e = Engine::new(cfg());
        let mut ev = NetEvent::inbound_new(0, Proto::Tcp, ip(1), 80);
        ev.direction = Direction::Outbound;
        for i in 0..50 {
            ev.ts_ms = i;
            assert_eq!(e.inspect(&ev), Verdict::Pass, "outbound not rate-limited");
        }
    }

    // ---- Port-scan detector ------------------------------------------------

    #[test]
    fn scan_trips_on_many_distinct_ports() {
        let mut e = Engine::new(cfg());
        let scanner = ip(3);
        // threshold is > 6 distinct ports within 2000ms. Space probes 300ms
        // apart so at most ~4 land in the 1000ms DDoS window (< 5) and the flood
        // detector never fires first — this isolates the scan logic.
        for p in 0..6u16 {
            let ev = NetEvent::inbound_new(p as u64 * 300, Proto::Tcp, scanner, 1000 + p);
            assert_eq!(e.inspect(&ev), Verdict::Pass, "port {p} should pass");
        }
        let ev = NetEvent::inbound_new(6 * 300, Proto::Tcp, scanner, 1006);
        let v = e.inspect(&ev);
        assert!(v.is_block(), "7th distinct port must flag a scan");
        if let Verdict::Block { reason, .. } = v {
            assert_eq!(reason, BlockReason::PortScan);
        }
    }

    #[test]
    fn scan_does_not_trip_on_repeated_same_port() {
        let mut e = Engine::new(cfg());
        let noisy = ip(4);
        // 50 hits, all to the SAME port => not a scan (rate limiter would catch
        // a flood, but we disable ddos here to isolate the scan logic).
        e.set_ddos_enabled(false);
        for i in 0..50u64 {
            let ev = NetEvent::inbound_new(i * 10, Proto::Tcp, noisy, 443);
            assert_eq!(
                e.inspect(&ev),
                Verdict::Pass,
                "same-port repeats aren't a scan"
            );
        }
    }

    #[test]
    fn scan_window_slides() {
        let mut e = Engine::new(cfg());
        let slow_scanner = ip(5);
        // One new port every 500ms. Window is 2000ms, so at most ~4-5 distinct
        // ports coexist => never exceeds threshold of 6.
        for p in 0..40u16 {
            let ev = NetEvent::inbound_new(p as u64 * 500, Proto::Tcp, slow_scanner, 3000 + p);
            assert_eq!(
                e.inspect(&ev),
                Verdict::Pass,
                "slow scan stays under window"
            );
        }
    }

    // ---- Whitelist + manual ------------------------------------------------

    #[test]
    fn whitelist_bypasses_all_detection() {
        let mut e = Engine::new(cfg());
        let trusted = ip(1);
        e.whitelist_add(trusted);
        for i in 0..100 {
            let ev = NetEvent::inbound_new(i, Proto::Tcp, trusted, (i % 200) as u16);
            assert_eq!(e.inspect(&ev), Verdict::Pass, "whitelisted never blocked");
        }
    }

    #[test]
    fn manual_block_is_enforced_and_liftable() {
        let mut e = Engine::new(cfg());
        let bad = ip(7);
        e.block_manual(bad, 5_000);
        assert!(e
            .inspect(&NetEvent::inbound_new(100, Proto::Tcp, bad, 22))
            .is_block());
        e.unblock(&bad);
        assert_eq!(
            e.inspect(&NetEvent::inbound_new(200, Proto::Tcp, bad, 22)),
            Verdict::Pass
        );
    }

    // ---- Metrics -----------------------------------------------------------

    #[test]
    fn metrics_bucket_and_series() {
        let mut m = Metrics::new(1_000, 5);
        // two events in bucket 0, one in bucket 1
        let e0 = NetEvent::inbound_new(100, Proto::Tcp, ip(1), 80);
        let e1 = NetEvent::inbound_new(200, Proto::Tcp, ip(2), 80);
        let e2 = NetEvent::inbound_new(1_100, Proto::Tcp, ip(1), 80);
        m.record(&e0, &Verdict::Pass);
        m.record(
            &e1,
            &Verdict::Block {
                until_ms: 9_999,
                reason: BlockReason::RateLimit,
            },
        );
        m.record(&e2, &Verdict::Pass);
        let s = m.series();
        assert_eq!(s.len(), 2, "two time buckets");
        assert_eq!(s[0].events, 2);
        assert_eq!(s[0].blocked, 1);
        assert_eq!(s[0].ratelimit_blocks, 1);
        assert_eq!(s[0].unique_ips, 2);
        assert_eq!(s[1].events, 1);
        assert_eq!(s[1].passed, 1);
    }

    #[test]
    fn metrics_ring_capacity() {
        let mut m = Metrics::new(1_000, 3);
        for sec in 0..10u64 {
            let ev = NetEvent::inbound_new(sec * 1_000 + 50, Proto::Tcp, ip(1), 80);
            m.record(&ev, &Verdict::Pass);
        }
        let s = m.series();
        assert_eq!(s.len(), 3, "ring keeps only the last 3 buckets");
        assert_eq!(s[2].t_ms, 9_000, "newest bucket retained");
    }

    // ---- Config round-trip -------------------------------------------------

    #[test]
    fn config_json_roundtrip() {
        let c = cfg();
        let json = c.to_json();
        let back = Config::from_json(&json).expect("parse");
        assert_eq!(c, back);
    }
}
