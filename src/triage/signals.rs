//! Signal engine: lightweight, explainable "AI" triage.
//!
//! Each signal independently evaluates a session against the triage context and
//! returns an optional piece of evidence. The controller aggregates them into a
//! single risk score and a human-readable rationale, which is what gets written
//! to the audit log for every enforced isolation.

use std::time::Duration;

use crate::flow::Session;
use crate::protocol::L7App;
use crate::triage::context::{TriageContext, is_private, is_sensitive_service};

#[derive(Debug, Clone, Copy)]
pub struct Signal {
    pub id: &'static str,
    pub weight: f64,
    pub eval: fn(&Session, &TriageContext, u64) -> Option<Evidence>,
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub contribution: f64, // 0..=1 how strongly this signal fired
    pub evidence: String,
}

impl Evidence {
    fn new(contribution: f64, evidence: String) -> Option<Self> {
        if contribution <= 0.0 {
            None
        } else {
            Some(Evidence { contribution, evidence })
        }
    }
}

fn rate(s: &Session, now_ns: u64) -> f64 {
    let dur = Duration::from_nanos(now_ns.saturating_sub(s.first_seen_ns));
    let secs = dur.as_secs_f64().max(0.001);
    s.packets as f64 / secs
}

fn byte_rate(s: &Session, now_ns: u64) -> f64 {
    let dur = Duration::from_nanos(now_ns.saturating_sub(s.first_seen_ns));
    let secs = dur.as_secs_f64().max(0.001);
    s.bytes as f64 / secs
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

fn signal_port_scan(s: &Session, ctx: &TriageContext, now_ns: u64) -> Option<Evidence> {
    let _ = now_ns;
    let src = s.key.src_ip();
    let dst = s.key.dst_ip();
    let ports = ctx.distinct_ports_to(&src, &dst);
    let ips = ctx.distinct_dst_ips(&src);
    if ports >= 10 || ips >= 20 {
        let contribution = ((ports as f64).max(ips as f64) / 15.0).min(1.0);
        Evidence::new(
            contribution,
            format!(
                "port scan pattern: {} distinct ports to {} and {} distinct destinations from {}",
                ports, dst, ips, src
            ),
        )
    } else {
        None
    }
}

fn signal_syn_flood(s: &Session, ctx: &TriageContext, _now_ns: u64) -> Option<Evidence> {
    if s.proto != 6 || s.syn_count == 0 {
        return None;
    }
    let ack_seen = s.tcp_flags_or & 0x10 != 0;
    let syn_rate = s.syn_count as f64 / ((s.last_seen_ns.saturating_sub(s.first_seen_ns)
        as f64 / 1e9).max(0.001));
    let _ = ctx;
    if !ack_seen && s.syn_count >= 8 {
        Evidence::new(
            1.0,
            format!(
                "SYN flood: {} SYN packets without any ACK in session {}",
                s.syn_count, s.key.dport
            ),
        )
    } else if syn_rate > 40.0 {
        Evidence::new(1.0, format!("SYN flood: {:.0} SYNs/sec", syn_rate))
    } else {
        None
    }
}

fn signal_unidirectional_udp(s: &Session, _ctx: &TriageContext, now_ns: u64) -> Option<Evidence> {
    if s.proto != 17 {
        return None;
    }
    let r = rate(s, now_ns);
    if r > 200.0 && s.bytes > 100_000 {
        Evidence::new(
            (r / 2000.0).min(1.0),
            format!(
                "unidirectional UDP burst: {:.0} pps / {:.0} KB/s from {}:{}",
                r,
                byte_rate(s, now_ns) / 1000.0,
                s.key.src_ip(),
                s.key.sport
            ),
        )
    } else {
        None
    }
}

fn signal_dns_tunnel(s: &Session, _ctx: &TriageContext, now_ns: u64) -> Option<Evidence> {
    if s.l7_app != L7App::Dns as u8 {
        return None;
    }
    let r = rate(s, now_ns);
    if s.l7_info > 40 && s.packets > 50 {
        Evidence::new(
            1.0,
            format!(
                "DNS tunneling: {:.0} pps with query names ~{} bytes long",
                r, s.l7_info
            ),
        )
    } else if s.l7_info > 30 && r > 10.0 {
        Evidence::new(0.6, format!("high-rate DNS ({:.0} pps) with long labels", r))
    } else {
        None
    }
}

fn signal_first_contact(s: &Session, ctx: &TriageContext, now_ms: u64) -> Option<Evidence> {
    let src = s.key.src_ip();
    if ctx.src_is_new(&src, now_ms) && !is_private(src) {
        Evidence::new(
            0.8,
            format!(
                "first contact from unseen source {} to {}:{}",
                src, s.key.dst_ip(), s.key.dport
            ),
        )
    } else {
        None
    }
}

fn signal_data_exfil(s: &Session, _ctx: &TriageContext, now_ns: u64) -> Option<Evidence> {
    let br = byte_rate(s, now_ns);
    let enc = s.l7_app == L7App::Tls as u8;
    let unusual_port = s.key.dport >= 1000 && s.key.dport != 443 && !crate::triage::context::is_ephemeral(s.key.dport);
    if br > 250_000.0 && (enc || unusual_port) {
        Evidence::new(
            (br / 2_000_000.0).min(1.0),
            format!(
                "possible data exfiltration: {:.0} KB/s {} to {}:{}",
                br / 1000.0,
                if enc { "encrypted" } else { "raw" },
                s.key.dst_ip(),
                s.key.dport
            ),
        )
    } else {
        None
    }
}

fn signal_rst_flood(s: &Session, _ctx: &TriageContext, _now_ns: u64) -> Option<Evidence> {
    if s.proto == 6 && s.packets > 0 {
        let ratio = s.rst_count as f64 / s.packets as f64;
        if ratio > 0.35 && s.rst_count > 10 {
            Evidence::new(
                (ratio - 0.35) / 0.35,
                format!(
                    "abnormal RST ratio {:.0}% ({} RSTs): torn-down / scanning session",
                    ratio * 100.0,
                    s.rst_count
                ),
            )
        } else {
            None
        }
    } else {
        None
    }
}

fn signal_lateral_movement(s: &Session, _ctx: &TriageContext, _now_ns: u64) -> Option<Evidence> {
    if s.proto == 6
        && is_private(s.key.src_ip())
        && is_private(s.key.dst_ip())
        && is_sensitive_service(s.key.dport)
        && s.syn_count > 5
        && s.tcp_flags_or & 0x10 == 0
    {
        Evidence::new(
            1.0,
            format!(
                "zero-trust violation: unexpected internal access {} -> {}:{} ({} SYN retries, no ACK)",
                s.key.src_ip(),
                s.key.dst_ip(),
                s.key.dport,
                s.syn_count
            ),
        )
    } else {
        None
    }
}

fn signal_slow_drip(s: &Session, _ctx: &TriageContext, _now_ns: u64) -> Option<Evidence> {
    if s.proto == 17 && s.packets > 500 && s.last_seen_ns.saturating_sub(s.first_seen_ns) > 5_000_000_000 {
        Evidence::new(
            0.5,
            format!(
                "slow drip volumetric UDP: {} packets over {}s",
                s.packets,
                (s.last_seen_ns - s.first_seen_ns) / 1_000_000_000
            ),
        )
    } else {
        None
    }
}

/// The full signal registry, ordered by relevance.
pub fn registry() -> Vec<Signal> {
    vec![
        Signal { id: "port_scan", weight: 0.9, eval: signal_port_scan },
        Signal { id: "syn_flood", weight: 0.95, eval: signal_syn_flood },
        Signal { id: "dns_tunnel", weight: 0.85, eval: signal_dns_tunnel },
        Signal { id: "data_exfil", weight: 0.9, eval: signal_data_exfil },
        Signal { id: "lateral_movement", weight: 0.85, eval: signal_lateral_movement },
        Signal { id: "unidirectional_udp", weight: 0.6, eval: signal_unidirectional_udp },
        Signal { id: "rst_flood", weight: 0.6, eval: signal_rst_flood },
        Signal { id: "slow_drip", weight: 0.4, eval: signal_slow_drip },
        Signal { id: "first_contact", weight: 0.3, eval: signal_first_contact },
    ]
}
