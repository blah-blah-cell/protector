//! Triage context: cross-session aggregates the signal engine needs.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::flow::{Session, SessionState};
use crate::protocol::L7App;

const WINDOW_MS: u64 = 300_000; // 5 minutes of history for aggregate signals

#[derive(Default)]
pub struct TriageContext {
    /// Src IPs seen within the window (wall-clock ms of first sighting).
    pub first_seen_src: HashMap<IpAddr, u64>,
    /// (src, dst) -> distinct dst ports seen.
    pub dst_ports: HashMap<(IpAddr, IpAddr), HashSet<u16>>,
    /// src -> distinct dst IPs.
    pub dst_ips: HashMap<IpAddr, HashSet<IpAddr>>,
    /// src -> number of active sessions.
    pub src_flow_count: HashMap<IpAddr, usize>,
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            o[0] == 10
                || o[0] == 172 && (16..=31).contains(&o[1])
                || o[0] == 192 && o[1] == 168
                || v.is_loopback()
        }
        IpAddr::V6(v) => v.is_loopback() || v.is_unique_local(),
    }
}

/// Service ports worth flagging for zero-trust lateral-movement heuristics.
pub fn is_sensitive_service(port: u16) -> bool {
    matches!(
        port,
        22 | 23 | 445 | 139 | 3389 | 5985 | 3306 | 5432 | 27017 | 6379 | 2375
    )
}

pub fn is_ephemeral(port: u16) -> bool {
    port >= 32768
}

impl TriageContext {
    pub fn rebuild(sessions: &HashMap<crate::protocol::FlowKey, Session>, now_ms: u64) -> Self {
        let mut ctx = TriageContext::default();
        for s in sessions.values() {
            if s.state == SessionState::Expired {
                continue;
            }
            let src = s.key.src_ip();
            let dst = s.key.dst_ip();
            ctx.first_seen_src.entry(src).or_insert(now_ms);
            ctx.dst_ports.entry((src, dst)).or_default().insert(s.key.dport);
            ctx.dst_ips.entry(src).or_default().insert(dst);
            *ctx.src_flow_count.entry(src).or_insert(0) += 1;
        }
        ctx.prune(now_ms);
        ctx
    }

    fn prune(&mut self, now_ms: u64) {
        self.first_seen_src
            .retain(|_, t| now_ms.saturating_sub(*t) <= WINDOW_MS);
    }

    pub fn src_is_new(&self, src: &IpAddr, now_ms: u64) -> bool {
        self.first_seen_src
            .get(src)
            .map(|t| now_ms.saturating_sub(*t) < 60_000)
            .unwrap_or(true)
    }

    pub fn distinct_ports_to(&self, src: &IpAddr, dst: &IpAddr) -> usize {
        self.dst_ports
            .get(&(*src, *dst))
            .map(HashSet::len)
            .unwrap_or(0)
    }

    pub fn distinct_dst_ips(&self, src: &IpAddr) -> usize {
        self.dst_ips.get(src).map(HashSet::len).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn app_is(s: &Session, app: L7App) -> bool {
        s.l7_app == app as u8
    }
}
