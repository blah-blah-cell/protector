//! Wire protocol shared with the eBPF programs.
//!
//! Every struct here mirrors a `struct` in `bpf/firewall.bpf.c` with an
//! identical in-memory layout so values can be exchanged through BPF maps and
//! the ring buffer without serialization.
#![allow(dead_code)]

use std::net::IpAddr;

/// Map indices into the `counters` array map (must match `bpf/firewall.bpf.c`).
pub const COUNTER_PASS: u32 = 0;
pub const COUNTER_DROP: u32 = 1;
pub const COUNTER_BLOCK_HITS: u32 = 2;
pub const COUNTER_NEW_FLOWS: u32 = 3;
pub const COUNTER_MALFORMED: u32 = 4;

/// `ctl` array index.
pub const CTL_INDEX: u32 = 0;

/// Control/configure flags (must match `ZQFW_*` in the C source).
pub const MODE_MONITOR: u32 = 0;
pub const MODE_ENFORCE: u32 = 1;
pub const FLAG_BLOCK_IP: u32 = 1 << 0;
pub const FLAG_HIT_EVENTS: u32 = 1 << 1;

/// Event kinds emitted into the `events` ring buffer.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    NewFlow = 1,
    BlockHit = 2,
    FlowExpired = 3,
    Drop = 4,
}

impl EventKind {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::NewFlow),
            2 => Some(Self::BlockHit),
            3 => Some(Self::FlowExpired),
            4 => Some(Self::Drop),
            _ => None,
        }
    }
}

/// L7 application identifiers (must match `L7_*` in the C source).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L7App {
    #[default]
    None = 0,
    Http = 1,
    Tls = 2,
    Dns = 3,
    Ssh = 4,
    Dhcp = 5,
    Quic = 6,
    UnknownTcp = 10,
    UnknownUdp = 11,
}

impl L7App {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Http,
            2 => Self::Tls,
            3 => Self::Dns,
            4 => Self::Ssh,
            5 => Self::Dhcp,
            6 => Self::Quic,
            10 => Self::UnknownTcp,
            11 => Self::UnknownUdp,
            _ => Self::None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "unknown",
            Self::Http => "HTTP",
            Self::Tls => "TLS",
            Self::Dns => "DNS",
            Self::Ssh => "SSH",
            Self::Dhcp => "DHCP",
            Self::Quic => "QUIC",
            Self::UnknownTcp => "tcp",
            Self::UnknownUdp => "udp",
        }
    }
}

/// Blocklist reason codes (must match `REASON_*` in the C source).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    Triage = 1,
    IpQuarantine = 2,
    RateLimit = 3,
    Manual = 4,
    Exfil = 5,
}

impl BlockReason {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Triage,
            2 => Self::IpQuarantine,
            3 => Self::RateLimit,
            4 => Self::Manual,
            5 => Self::Exfil,
            _ => Self::Triage,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::IpQuarantine => "ip_quarantine",
            Self::RateLimit => "rate_limit",
            Self::Manual => "manual",
            Self::Exfil => "data_exfiltration",
        }
    }
}

/// 5-tuple (+direction) key. Layout must match `struct flow_key`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct FlowKey {
    /// 16 bytes; IPv4 uses `[0]`, the rest stay zero.
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub dir: u8,
}

/// Source-IP quarantine key. Layout must match `struct ip_key`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IpKey {
    pub addr: [u32; 4],
}

/// Per-flow metrics. Layout must match `struct flow_metrics`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct FlowMetrics {
    pub packets: u64,
    pub bytes: u64,
    pub sum_pkt_len: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub max_pkt_len: u32,
    pub min_pkt_len: u32,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub tcp_flags_or: u16,
    pub l7_app: u16,
    pub l7_info: u16,
    pub proto: u8,
    pub emitted: u8,
}

/// Blocklist entry. Layout must match `struct block_entry`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct BlockEntry {
    pub reason: u32,
    pub ts_ns: u32,
    pub ttl_ns: u32,
    pub seq: u32,
}

/// Control/configuration. Layout must match `struct zqfw_cfg`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ControlCfg {
    pub mode: u32,
    pub flags: u32,
    pub block_ttl_ns: u32,
    pub reserved: u32,
}

/// Aggregate counters. Layout must match `struct zqfw_counter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CounterVec {
    pub pass: u64,
    pub drop: u64,
    pub block_hits: u64,
    pub new_flows: u64,
    pub malformed: u64,
    pub events_lost: u64,
}

/// Ring-buffer event. Layout must match `struct zqfw_event`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct KernelEvent {
    pub kind: u32,
    pub ts_ns: u32,
    pub len: u32,
    pub cpu: u32,
    pub key: FlowKey,
    pub l7_app: u16,
    pub l7_info: u16,
}

impl KernelEvent {
    pub fn event_kind(&self) -> EventKind {
        EventKind::from_u32(self.kind).unwrap_or(EventKind::Drop)
    }
}

impl FlowKey {
    pub fn src_ip(&self) -> IpAddr {
        if self.proto == 58 || self.saddr[1] != 0 || self.saddr[2] != 0 || self.saddr[3] != 0 {
            IpAddr::V6(std::net::Ipv6Addr::new(
                (self.saddr[0] >> 16) as u16,
                self.saddr[0] as u16,
                (self.saddr[1] >> 16) as u16,
                self.saddr[1] as u16,
                (self.saddr[2] >> 16) as u16,
                self.saddr[2] as u16,
                (self.saddr[3] >> 16) as u16,
                self.saddr[3] as u16,
            ))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::from(self.saddr[0]))
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        if self.proto == 58 || self.daddr[1] != 0 || self.daddr[2] != 0 || self.daddr[3] != 0 {
            IpAddr::V6(std::net::Ipv6Addr::new(
                (self.daddr[0] >> 16) as u16,
                self.daddr[0] as u16,
                (self.daddr[1] >> 16) as u16,
                self.daddr[1] as u16,
                (self.daddr[2] >> 16) as u16,
                self.daddr[2] as u16,
                (self.daddr[3] >> 16) as u16,
                self.daddr[3] as u16,
            ))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::from(self.daddr[0]))
        }
    }

    pub fn reverse(&self) -> FlowKey {
        FlowKey {
            saddr: self.daddr,
            daddr: self.saddr,
            sport: self.dport,
            dport: self.sport,
            proto: self.proto,
            dir: 1,
        }
    }
}

impl IpKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        let mut addr = [0u32; 4];
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                addr[0] = u32::from_be_bytes(o);
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                for (chunk, bytes) in addr.iter_mut().zip(o.chunks(4)) {
                    *chunk = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                }
            }
        }
        IpKey { addr }
    }

    pub fn to_ip(&self) -> IpAddr {
        if self.addr[1] != 0 || self.addr[2] != 0 || self.addr[3] != 0 {
            let mut b = [0u8; 16];
            for (chunk, bytes) in self.addr.iter().zip(b.chunks_mut(4)) {
                bytes.copy_from_slice(&chunk.to_be_bytes());
            }
            IpAddr::V6(std::net::Ipv6Addr::from(b))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::from(self.addr[0]))
        }
    }
}

// SAFETY: these are plain-old-data mirror structs exchanged byte-for-byte with
// the kernel through BPF maps / ring buffers.
unsafe impl aya::Pod for FlowKey {}
unsafe impl aya::Pod for IpKey {}
unsafe impl aya::Pod for FlowMetrics {}
unsafe impl aya::Pod for BlockEntry {}
unsafe impl aya::Pod for ControlCfg {}
unsafe impl aya::Pod for CounterVec {}
unsafe impl aya::Pod for KernelEvent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_key_size() {
        // Must match the C layout: 4+4 u32s + 2 u16s + 2 u8s = 40 bytes.
        assert_eq!(std::mem::size_of::<FlowKey>(), 40);
    }

    #[test]
    fn ip_roundtrip_v4() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(IpKey::from_ip(ip).to_ip(), ip);
    }

    #[test]
    fn ip_roundtrip_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(IpKey::from_ip(ip).to_ip(), ip);
    }

    #[test]
    fn flow_key_ip_roundtrip() {
        let mut k = FlowKey::default();
        k.saddr[0] = u32::from_be_bytes([10, 1, 2, 3]);
        assert_eq!(k.src_ip(), "10.1.2.3".parse::<IpAddr>().unwrap());
    }
}
