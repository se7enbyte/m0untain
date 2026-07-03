//! The network-event model.
//!
//! A `NetEvent` is one observation surfaced from the WFP layer on Windows
//! (or synthesised in a unit test). The detection engine only ever sees this
//! struct, which is exactly why the engine is platform-independent and
//! testable on any OS.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other,
}

/// What WFP actually did / will do with the packet at the moment we saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Allow,
    Block,
}

/// A single network event. `ts_ms` is a millisecond timestamp; making time an
/// explicit field (rather than reading a global clock) is what makes the
/// detectors deterministic under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEvent {
    pub ts_ms: u64,
    pub direction: Direction,
    pub proto: Proto,
    pub local_ip: IpAddr,
    /// Port on THIS host. For inbound traffic this is the port being probed.
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub pid: u32,
    /// Owning process image path, if resolved.
    pub app_path: Option<String>,
    /// Windows service SID, when the flow belongs to a shared svchost service.
    /// This is how we split "svchost" into the actual service (lesson learned
    /// from simplewall silently trusting all of svchost).
    pub service_sid: Option<String>,
    /// True when this is a *new* flow/connection attempt (ALE auth connect /
    /// auth recv-accept), as opposed to an already-established flow. Rate and
    /// scan detection only count new attempts.
    pub is_new_conn: bool,
    /// What the base firewall verdict was (before our detectors weigh in).
    pub action: Action,
}

impl NetEvent {
    /// Convenience constructor used heavily in tests.
    #[allow(clippy::too_many_arguments)]
    pub fn inbound_new(ts_ms: u64, proto: Proto, remote_ip: IpAddr, local_port: u16) -> Self {
        use std::net::{IpAddr, Ipv4Addr};
        NetEvent {
            ts_ms,
            direction: Direction::Inbound,
            proto,
            local_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port,
            remote_ip,
            remote_port: 40000,
            pid: 0,
            app_path: None,
            service_sid: None,
            is_new_conn: true,
            action: Action::Allow,
        }
    }
}
