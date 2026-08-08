//! In-memory session model used by the triage controller.

use std::collections::HashMap;

use crate::protocol::{FlowKey, FlowMetrics, KernelEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    New,
    Active,
    Suspicious,
    Quarantined,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub key: FlowKey,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub bytes: u64,
    pub sum_pkt_len: u64,
    pub max_pkt_len: u32,
    pub min_pkt_len: u32,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub tcp_flags_or: u16,
    pub l7_app: u8,
    pub l7_info: u16,
    pub proto: u8,
    pub risk: f64,
    pub state: SessionState,
    /// Wall-clock ms when the quarantine expires, if any.
    pub quarantine_until_ms: Option<u64>,
    pub block_seq: Option<u64>,
}

impl Session {
    pub fn from_event(ev: &KernelEvent, now_ns: u64) -> Self {
        Session {
            key: ev.key,
            first_seen_ns: now_ns,
            last_seen_ns: now_ns,
            packets: 1,
            bytes: ev.len as u64,
            sum_pkt_len: ev.len as u64,
            max_pkt_len: ev.len,
            min_pkt_len: ev.len,
            syn_count: 0,
            fin_count: 0,
            rst_count: 0,
            tcp_flags_or: 0,
            l7_app: ev.l7_app as u8,
            l7_info: ev.l7_info,
            proto: ev.key.proto,
            risk: 0.0,
            state: SessionState::New,
            quarantine_until_ms: None,
            block_seq: None,
        }
    }

    pub fn merge_metrics(&mut self, m: &FlowMetrics) {
        self.first_seen_ns = self.first_seen_ns.min(m.first_seen_ns as u64);
        self.last_seen_ns = self.last_seen_ns.max(m.last_seen_ns as u64);
        self.packets = m.packets;
        self.bytes = m.bytes;
        self.sum_pkt_len = m.sum_pkt_len;
        self.max_pkt_len = m.max_pkt_len.max(self.max_pkt_len);
        if m.min_pkt_len > 0 {
            self.min_pkt_len = if self.min_pkt_len == 0 {
                m.min_pkt_len
            } else {
                self.min_pkt_len.min(m.min_pkt_len)
            };
        }
        self.syn_count = m.syn_count;
        self.fin_count = m.fin_count;
        self.rst_count = m.rst_count;
        self.tcp_flags_or = m.tcp_flags_or;
        if m.l7_app != 0 {
            self.l7_app = m.l7_app as u8;
            self.l7_info = m.l7_info;
        }
        self.proto = m.proto;
        if self.state == SessionState::New && m.packets > 1 {
            self.state = SessionState::Active;
        }
    }
}

#[derive(Default)]
pub struct SessionTable {
    pub sessions: HashMap<FlowKey, Session>,
}

impl SessionTable {
    pub fn upsert_from_event(&mut self, ev: &KernelEvent, now_ns: u64) {
        match self.sessions.get_mut(&ev.key) {
            Some(s) => {
                s.last_seen_ns = now_ns;
                s.packets += 1;
                s.bytes += ev.len as u64;
                s.sum_pkt_len += ev.len as u64;
                if s.state == SessionState::New {
                    s.state = SessionState::Active;
                }
                if ev.l7_app as u8 != 0 && s.l7_app == 0 {
                    s.l7_app = ev.l7_app as u8;
                    s.l7_info = ev.l7_info;
                }
            }
            None => {
                let s = Session::from_event(ev, now_ns);
                self.sessions.insert(ev.key, s);
            }
        }
    }

    pub fn merge_metrics(&mut self, key: FlowKey, m: &FlowMetrics) {
        self.sessions
            .entry(key)
            .or_insert_with(|| Session {
                key,
                first_seen_ns: m.first_seen_ns as u64,
                last_seen_ns: m.last_seen_ns as u64,
                packets: 0,
                bytes: 0,
                sum_pkt_len: 0,
                max_pkt_len: 0,
                min_pkt_len: 0,
                syn_count: 0,
                fin_count: 0,
                rst_count: 0,
                tcp_flags_or: 0,
                l7_app: 0,
                l7_info: 0,
                proto: m.proto,
                risk: 0.0,
                state: SessionState::New,
                quarantine_until_ms: None,
                block_seq: None,
            })
            .merge_metrics(m);
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<Session> {
        self.sessions.remove(key)
    }
}
