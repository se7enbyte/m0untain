//! Simulator backend. Generates realistic inbound traffic with periodic flood
//! and port-scan bursts, so the full detection pipeline and dashboard can run
//! and be validated on any platform without WFP. Block/unblock are no-ops that
//! just hand back handles.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{AppProtocol, Firewall, RawConn, RemoteMatch};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub struct SimFirewall {
    next_handle: Arc<AtomicU64>,
}

impl SimFirewall {
    pub fn start(tx: Sender<RawConn>) -> Result<Self, String> {
        thread::spawn(move || run(tx));
        Ok(SimFirewall {
            next_handle: Arc::new(AtomicU64::new(1)),
        })
    }
}

impl Firewall for SimFirewall {
    fn block_ip(&self, _ip: IpAddr) -> Result<u64, String> {
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }
    fn block_app(&self, _app_id: &[u8], _protocol: AppProtocol) -> Result<u64, String> {
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }
    fn block_app_target(
        &self,
        _app_id: &[u8],
        _protocol: AppProtocol,
        _remote: Option<RemoteMatch>,
        _remote_port: Option<u16>,
    ) -> Result<u64, String> {
        Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
    }
    fn unblock(&self, _handle: u64) -> Result<(), String> {
        Ok(())
    }
    fn backend(&self) -> &'static str {
        "Simulator"
    }
}

// Tiny deterministic-ish PRNG so we don't pull in the rand crate.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn upto(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn rip(r: &mut Rng) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        185 + r.upto(3) as u8,
        r.upto(255) as u8,
        r.upto(255) as u8,
        1 + r.upto(254) as u8,
    ))
}

enum Attack {
    Flood { ip: IpAddr, left: u32 },
    Scan { ip: IpAddr, left: u32, port: u16 },
}

fn run(tx: Sender<RawConn>) {
    let mut r = Rng(0x9E3779B97F4A7C15 ^ now_ms());
    let mut attack: Option<Attack> = None;

    loop {
        let t = now_ms();

        // baseline: a handful of benign inbound + outbound conns this tick
        let benign = 8 + r.upto(10) as u32;
        for _ in 0..benign {
            let inbound = r.upto(10) < 6;
            let _ = tx.send(RawConn {
                ts_ms: t,
                inbound,
                is_new: true,
                udp: r.upto(10) < 3,
                remote_ip: rip(&mut r),
                remote_port: 1024 + r.upto(60000) as u16,
                local_port: [80u16, 443, 22, 3389, 53][r.upto(5) as usize],
                pid: 1000 + r.upto(400) as u32,
                app_id: None,
                app_path: None,
            });
        }

        // maybe launch an attack
        if attack.is_none() && r.upto(100) < 8 {
            let ip = rip(&mut r);
            attack = Some(if r.upto(2) == 0 {
                Attack::Flood {
                    ip,
                    left: 4 + r.upto(6) as u32,
                }
            } else {
                Attack::Scan {
                    ip,
                    left: 4 + r.upto(4) as u32,
                    port: 1,
                }
            });
        }

        match attack.as_mut() {
            Some(Attack::Flood { ip, left }) => {
                for _ in 0..(80 + r.upto(60)) {
                    let _ = tx.send(RawConn {
                        ts_ms: t,
                        inbound: true,
                        is_new: true,
                        udp: false,
                        remote_ip: *ip,
                        remote_port: 40000 + r.upto(20000) as u16,
                        local_port: 443,
                        pid: 0,
                        app_id: None,
                        app_path: None,
                    });
                }
                *left -= 1;
                if *left == 0 {
                    attack = None;
                }
            }
            Some(Attack::Scan { ip, left, port }) => {
                for _ in 0..25 {
                    let _ = tx.send(RawConn {
                        ts_ms: t,
                        inbound: true,
                        is_new: true,
                        udp: false,
                        remote_ip: *ip,
                        remote_port: 44444,
                        local_port: *port,
                        pid: 0,
                        app_id: None,
                        app_path: None,
                    });
                    *port = port.wrapping_add(1).max(1);
                }
                *left -= 1;
                if *left == 0 {
                    attack = None;
                }
            }
            None => {}
        }

        thread::sleep(Duration::from_millis(1000));
    }
}
