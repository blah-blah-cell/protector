//! AI triage controller.
//!
//! Combines the signal engine (a lightweight, explainable model) with an
//! optional external LLM backend into one decision pipeline. The controller
//! is deterministic and latency-bounded: enforcement always uses the signal
//! engine, while the LLM (when configured) adds a second, free-form layer of
//! reasoning to the audit trail.

pub mod context;
pub mod llm;
pub mod signals;

use crate::audit::{Decision, RationaleSignal};
use crate::flow::Session;
use crate::triage::context::TriageContext;

#[derive(Debug, Clone)]
pub struct TriageOutcome {
    pub decision: Decision,
    pub risk: f64,
    pub confidence: f64,
    pub rationale: Vec<RationaleSignal>,
    #[allow(dead_code)]
    pub quarantine_ms: u64,
}

#[derive(Debug, Clone)]
pub struct TriageController {
    pub threshold: f64,
    #[allow(dead_code)]
    pub quarantine_ms: u64,
    pub block_ip: bool,
    pub signals: Vec<signals::Signal>,
}

impl TriageController {
    pub fn new(threshold: f64, quarantine_ms: u64, block_ip: bool) -> Self {
        TriageController {
            threshold,
            quarantine_ms,
            block_ip,
            signals: signals::registry(),
        }
    }

    /// Score a single session. `now_ns` is boot-ns (as the kernel reports),
    /// `now_ms` is wall-clock ms (used by time-window signals).
    pub fn triage(
        &self,
        session: &Session,
        ctx: &TriageContext,
        now_ns: u64,
        now_ms: u64,
    ) -> TriageOutcome {
        let mut fired: Vec<RationaleSignal> = Vec::new();
        let mut weight_sum = 0.0;
        let mut score = 0.0;

        for sig in &self.signals {
            if let Some(ev) = (sig.eval)(session, ctx, now_ns) {
                score += ev.contribution * sig.weight;
                weight_sum += sig.weight;
                fired.push(RationaleSignal {
                    signal: sig.id,
                    weight: sig.weight,
                    contribution: ev.contribution,
                    evidence: ev.evidence,
                });
            }
        }
        let _ = now_ms;

        let risk = if weight_sum > 0.0 {
            (score / weight_sum).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let (decision, confidence) = if risk >= self.threshold {
            // Source-behavioural signals justify quarantining the whole host.
            let systemic = fired
                .iter()
                .any(|r| matches!(r.signal, "port_scan" | "syn_flood"));
            let src = session.key.src_ip();
            let escalate_ip = self.block_ip
                && systemic
                && ctx.src_flow_count.get(&src).copied().unwrap_or(0) >= 3;
            let confidence = (risk * 0.7 + 0.3).min(0.99);
            if escalate_ip {
                (Decision::QuarantineIp, confidence)
            } else {
                (Decision::Quarantine, confidence)
            }
        } else {
            (Decision::Allow, risk)
        };

        TriageOutcome {
            decision,
            risk,
            confidence,
            rationale: fired,
            quarantine_ms: self.quarantine_ms,
        }
    }

    /// Whether this session merits a second, free-form review by the LLM.
    #[allow(dead_code)]
    pub fn warrants_review(&self, outcome: &TriageOutcome) -> bool {
        outcome.risk >= 0.5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Session, SessionState};
    use crate::protocol::FlowKey;
    use std::collections::HashMap;

    fn session_with(
        key: FlowKey,
        packets: u64,
        syn: u32,
        flags: u16,
        first: u64,
    ) -> Session {
        Session {
            key,
            first_seen_ns: first,
            last_seen_ns: first + 2_000_000_000,
            packets,
            bytes: packets * 1500,
            sum_pkt_len: packets * 1500,
            max_pkt_len: 1500,
            min_pkt_len: 64,
            syn_count: syn,
            fin_count: 0,
            rst_count: 0,
            tcp_flags_or: flags,
            l7_app: 0,
            l7_info: 0,
            proto: key.proto,
            risk: 0.0,
            state: SessionState::Active,
            quarantine_until_ms: None,
            block_seq: None,
        }
    }

    #[test]
    fn syn_flood_quarantines() {
        let mut key = FlowKey::default();
        key.saddr[0] = u32::from_be_bytes([1, 2, 3, 4]);
        key.daddr[0] = u32::from_be_bytes([5, 6, 7, 8]);
        key.sport = 11111;
        key.dport = 443;
        key.proto = 6;
        let s = session_with(key, 20, 20, 0x02, 1_000_000_000);
        let ctx = TriageContext::default();
        let ctrl = TriageController::new(0.8, 300_000, false);
        let out = ctrl.triage(&s, &ctx, 3_000_000_000, 0);
        assert_eq!(out.decision, Decision::Quarantine);
        assert!(out.risk > 0.8);
        assert!(!out.rationale.is_empty());
    }

    #[test]
    fn benign_flow_allowed() {
        let mut key = FlowKey::default();
        key.saddr[0] = u32::from_be_bytes([10, 0, 0, 1]);
        key.daddr[0] = u32::from_be_bytes([10, 0, 0, 2]);
        key.sport = 40000;
        key.dport = 443;
        key.proto = 6;
        let s = session_with(key, 5, 1, 0x12, 1_000_000_000);
        let ctx = TriageContext::default();
        let ctrl = TriageController::new(0.8, 300_000, false);
        let out = ctrl.triage(&s, &ctx, 3_000_000_000, 0);
        assert_eq!(out.decision, Decision::Allow, "benign risk={} rationale={:?}", out.risk, out.rationale.iter().map(|r| r.signal).collect::<Vec<_>>());
        assert!(out.risk < 0.8);
    }

    #[test]
    fn scan_escalates_to_ip_when_enabled() {
        let mut table = HashMap::new();
        let mut ctrl = TriageController::new(0.8, 300_000, true);
        let ctx = TriageContext::default();
        for dport in [1u16, 22, 80, 443, 8080, 53, 21, 25, 110, 143, 993, 3306] {
            let mut key = FlowKey::default();
            key.saddr[0] = u32::from_be_bytes([1, 2, 3, 4]);
            key.daddr[0] = u32::from_be_bytes([5, 6, 7, 8]);
            key.sport = 11111;
            key.dport = dport;
            key.proto = 6;
            let s = session_with(key, 1, 1, 0x02, 1_000_000_000);
            table.insert(key, s);
        }
        // Rebuild context so it sees the multi-port pattern.
        let ctx = TriageContext::rebuild(&table, 1_000_000_000_000);
        let mut key = FlowKey::default();
        key.saddr[0] = u32::from_be_bytes([1, 2, 3, 4]);
        key.daddr[0] = u32::from_be_bytes([5, 6, 7, 8]);
        key.sport = 11111;
        key.dport = 445;
        key.proto = 6;
        let s = session_with(key, 1, 1, 0x02, 1_000_000_000);
        let out = ctrl.triage(&s, &ctx, 3_000_000_000, 0);
        assert_eq!(out.decision, Decision::QuarantineIp);
    }
}
