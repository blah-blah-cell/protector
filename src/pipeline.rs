//! The supervisor event loop: consumes kernel events, maintains the session
//! table, runs triage, enforces quarantine by updating BPF maps, re-evaluates
//! and expires isolations, and writes the audit trail.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio::time::MissedTickBehavior;

use crate::audit::{ActionRef, AuditEvent, AuditLogger, Decision, FlowRef};
use crate::bpf::DataPlane;
use crate::config::Config;
use crate::flow::{SessionState, SessionTable};
use crate::protocol::{BlockEntry, BlockReason, EventKind, FlowKey, KernelEvent};
use crate::triage::context::TriageContext;
use crate::triage::{TriageController, TriageOutcome};

static BOOT_NANOS: AtomicU64 = AtomicU64::new(0);

/// Awaits the next Unix signal; yields immediately if the stream is missing.
async fn wait_signal(sig: Option<&mut tokio::signal::unix::Signal>) {
    if let Some(s) = sig {
        let _ = s.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Read the kernel's monotonic boot clock in ns (matches the probe's timestamps).
pub fn boot_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    let ns = (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64;
    BOOT_NANOS.store(ns, Ordering::Relaxed);
    ns
}

/// Snapshot of the world exposed to the metrics exporter.
#[derive(Default, Debug, Clone)]
pub struct MetricsState {
    pub pass: u64,
    pub drop: u64,
    pub block_hits: u64,
    pub new_flows: u64,
    pub malformed: u64,
    pub events_lost: u64,
    pub sessions: usize,
    pub quarantined_flows: usize,
    pub quarantined_ips: usize,
    pub decisions: u64,
    pub enforce: bool,
}

pub struct Supervisor {
    pub plane: Arc<Mutex<Box<dyn DataPlane + Send>>>,
    pub table: SessionTable,
    pub ctrl: TriageController,
    pub cfg: Config,
    pub metrics: Arc<Mutex<MetricsState>>,
    pub audit: Arc<Mutex<AuditLogger>>,
    pub enforce: bool,
    pub llm: Option<crate::triage::llm::LlmBackend>,
    pub quarantined_ips_expiry: Vec<(IpAddr, u64)>,
    pub decisions: std::sync::atomic::AtomicU64,
}

impl Supervisor {
    pub async fn run(&mut self, mut rx: Receiver<KernelEvent>) -> Result<()> {
        let mut triage_interval = tokio::time::interval(self.cfg.cli.reap_interval);
        triage_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        self.enforce = !self.cfg.cli.monitor;
        self.plane
            .lock()
            .await
            .apply_control(self.enforce, &self.cfg)?;

        self.audit.lock().await.log(AuditEvent {
            event: "supervisor_started",
            level: "info",
            flow: None,
            src_ip: None,
            risk: None,
            threshold: Some(self.ctrl.threshold),
            confidence: None,
            decision: Some(Decision::Monitor),
            rationale: vec![],
            action: Some(ActionRef {
                kind: "ctl",
                map: "ctl",
                key: "mode".into(),
                reason: if self.enforce { "enforce" } else { "monitor" },
                seq: 0,
                ttl_ns: self.cfg.block_ttl_ns,
            }),
            latency_ms: None,
            detail: Some(format!(
                "attach={} iface={} threshold={} quarantine={}s block_ip={} mock={}",
                if self.enforce { "enforce" } else { "monitor" },
                self.cfg.cli.iface,
                self.ctrl.threshold,
                self.cfg.cli.quarantine.as_secs(),
                self.cfg.block_ip,
                self.cfg.cli.mock
            )),
            ts: 0,
        });

        let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            .ok();
        let mut usr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
            .ok();

        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Some(ev) => self.on_event(ev),
                    None => { tracing::warn!("event channel closed, exiting"); break; }
                },
                _ = triage_interval.tick() => {
                    self.triage_tick().await;
                    self.reap_tick().await;
                    self.publish_metrics().await;
                }
                _ = wait_signal(usr1.as_mut()) => {
                    self.toggle_enforce().await;
                }
                _ = wait_signal(usr2.as_mut()) => {
                    self.dump_table().await;
                }
            }
        }
        Ok(())
    }

    fn on_event(&mut self, ev: KernelEvent) {
        match ev.event_kind() {
            EventKind::NewFlow => {
                self.table.upsert_from_event(&ev, boot_ns());
            }
            EventKind::BlockHit | EventKind::Drop | EventKind::FlowExpired => {}
        }
    }

    async fn triage_tick(&mut self) {
        let now_ns = boot_ns();
        let now_ms = crate::audit::now_ms();

        // Authoritative counters live in the kernel maps; merge them in.
        let snap = self.plane.lock().await.snapshot_flows();
        for (key, metrics) in snap {
            self.table.merge_metrics(key, &metrics);
        }

        let ctx = TriageContext::rebuild(&self.table.sessions, now_ms);

        let candidates: Vec<(FlowKey, crate::flow::Session)> = self
            .table
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.state != SessionState::Quarantined && s.state != SessionState::Expired
            })
            .filter(|(k, _)| {
                // A source already under IP quarantine is being dropped at the
                // data plane; skip re-scoring its remaining sessions.
                !self
                    .quarantined_ips_expiry
                    .iter()
                    .any(|(ip, _)| *ip == k.src_ip())
            })
            .map(|(k, s)| (*k, s.clone()))
            .collect();

        for (key, session) in candidates {
            let out = self.ctrl.triage(&session, &ctx, now_ns, now_ms);

            if out.risk >= 0.5 && self.llm.is_some() {
                self.request_llm_review(key, session.clone(), out.clone()).await;
            }

            match out.decision {
                Decision::Quarantine | Decision::QuarantineIp => {
                    self.enforce_isolation(key, session.clone(), out).await;
                }
                _ => {
                    if out.risk >= self.ctrl.threshold * 0.7 {
                        if let Some(s) = self.table.sessions.get_mut(&key) {
                            if matches!(s.state, SessionState::New | SessionState::Active) {
                                s.state = SessionState::Suspicious;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn enforce_isolation(
        &mut self,
        key: FlowKey,
        session: crate::flow::Session,
        out: TriageOutcome,
    ) {
        // One isolation per session: never re-enforce the same key.
        if let Some(s) = self.table.sessions.get(&key) {
            if s.state == SessionState::Quarantined {
                return;
            }
        }

        let seq = self.audit.lock().await.next_seq();
        let ts_ns = boot_ns();
        let is_ip = out.decision == Decision::QuarantineIp;

        // A source already under IP quarantine in this tick is being dropped at
        // the data plane; skip its remaining sessions entirely.
        if is_ip
            && self
                .quarantined_ips_expiry
                .iter()
                .any(|(ip, _)| *ip == key.src_ip())
        {
            return;
        }
        let entry = BlockEntry {
            reason: if is_ip {
                BlockReason::IpQuarantine as u32
            } else {
                BlockReason::Triage as u32
            },
            ts_ns: ts_ns as u32,
            ttl_ns: self.cfg.block_ttl_ns as u32,
            seq: seq as u32,
        };
        // Enforce: write the kernel map. This is the sub-millisecond isolation step.
        let started = Instant::now();
        let block_result = {
            let mut plane = self.plane.lock().await;
            if is_ip {
                let ipkey = crate::protocol::IpKey::from_ip(key.src_ip());
                let r = plane.block_ip(&ipkey, entry);
                if r.is_ok() {
                    let until = crate::audit::now_ms() + self.cfg.cli.quarantine.as_millis() as u64;
                    if !self.quarantined_ips_expiry.iter().any(|(i, _)| *i == key.src_ip()) {
                        self.quarantined_ips_expiry.push((key.src_ip(), until));
                    }
                }
                r
            } else {
                plane.block_flow(&key, entry)
            }
        };
        let latency = started.elapsed();

        if let Err(e) = block_result {
            tracing::error!("blocklist update failed for {key:?}: {e}");
            return;
        }
        self.decisions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Some(s) = self.table.sessions.get_mut(&key) {
            s.state = SessionState::Quarantined;
            s.risk = out.risk;
            s.quarantine_until_ms = Some(crate::audit::now_ms() + self.cfg.cli.quarantine.as_millis() as u64);
            s.block_seq = Some(seq);
        }

        let flow_ref = FlowRef::from_key(&key, session.packets, session.bytes);
        let action = ActionRef {
            kind: if is_ip { "ip_quarantine" } else { "flow_quarantine" },
            map: if is_ip { "blocklist_ip" } else { "blocklist" },
            key: if is_ip {
                format!("{}", key.src_ip())
            } else {
                format!("{}:{}->{}:{}", key.src_ip(), key.sport, key.dst_ip(), key.dport)
            },
            reason: if is_ip { "ip_quarantine" } else { "triage" },
            seq,
            ttl_ns: self.cfg.block_ttl_ns,
        };

        self.audit.lock().await.enforce(AuditEvent {
            event: "isolation_enforced",
            level: "alert",
            flow: Some(flow_ref),
            src_ip: Some(key.src_ip()),
            risk: Some(out.risk),
            threshold: Some(self.ctrl.threshold),
            confidence: Some(out.confidence),
            decision: Some(out.decision),
            rationale: out.rationale,
            action: Some(action),
            latency_ms: Some(latency.as_secs_f64() * 1000.0),
            detail: None,
            ts: crate::audit::now_ms(),
        });

        if is_ip {
            // Zero-trust: quarantine the reverse direction of the session too.
            let _ = {
                let mut plane = self.plane.lock().await;
                let rev = key.reverse();
                plane.block_flow(&rev, BlockEntry { ..entry })
            };
        }
    }

    async fn request_llm_review(&self, key: FlowKey, session: crate::flow::Session, out: TriageOutcome) {
        let Some(llm) = self.llm.clone() else { return };
        let audit = self.audit.clone();
        let summary = format!(
            "flow {} -> {}:{} proto={} app={} packets={} bytes={} syn={} risk={:.2} rationale={}",
            key.src_ip(),
            key.dst_ip(),
            key.dport,
            key.proto,
            session.l7_app,
            session.packets,
            session.bytes,
            session.syn_count,
            out.risk,
            out.rationale
                .iter()
                .map(|r| r.signal)
                .collect::<Vec<_>>()
                .join(",")
        );
        tokio::spawn(async move {
            match llm.review(&summary).await {
                Ok(text) => {
                    audit.lock().await.log(AuditEvent {
                        event: "llm_rationale",
                        level: "info",
                        flow: Some(FlowRef::from_key(&key, session.packets, session.bytes)),
                        src_ip: Some(key.src_ip()),
                        risk: Some(out.risk),
                        threshold: None,
                        confidence: None,
                        decision: Some(out.decision),
                        rationale: out.rationale,
                        action: None,
                        latency_ms: None,
                        detail: Some(text),
                        ts: crate::audit::now_ms(),
                    });
                }
                Err(e) => tracing::debug!("llm review failed: {e}"),
            }
        });
    }

    /// Expire idle sessions, re-evaluate quarantined ones (TTL), unblock.
    async fn reap_tick(&mut self) {
        let now_ns = boot_ns();
        let now_ms = crate::audit::now_ms();
        let flow_ttl_ns = self.cfg.cli.flow_ttl.as_nanos() as u64;

        let mut expired: Vec<FlowKey> = Vec::new();
        let mut release: Vec<FlowKey> = Vec::new();

        for (key, s) in self.table.sessions.iter() {
            let idle = now_ns.saturating_sub(s.last_seen_ns) > flow_ttl_ns;
            let ttl_expired = s
                .quarantine_until_ms
                .map(|until| now_ms >= until)
                .unwrap_or(false);

            if s.state == SessionState::Quarantined && (idle || ttl_expired) {
                release.push(*key);
            } else if idle {
                expired.push(*key);
            }
        }

        {
            let mut plane = self.plane.lock().await;
            for key in &release {
                plane.unblock_flow(key).ok();
                if let Some(s) = self.table.sessions.get_mut(key) {
                    s.state = SessionState::Active;
                    s.quarantine_until_ms = None;
                    s.block_seq = None;
                }
            }
            for key in &expired {
                self.table.remove(key);
            }
        }

        for key in &release {
            self.audit.lock().await.log(AuditEvent {
                event: "isolation_released",
                level: "info",
                flow: Some(FlowRef::from_key(key, 0, 0)),
                src_ip: Some(key.src_ip()),
                risk: None,
                threshold: Some(self.ctrl.threshold),
                confidence: None,
                decision: Some(Decision::Unquarantine),
                rationale: vec![],
                action: Some(ActionRef {
                    kind: "unblock",
                    map: "blocklist",
                    key: format!("{}:{}", key.dst_ip(), key.dport),
                    reason: "ttl_expired",
                    seq: 0,
                    ttl_ns: 0,
                }),
                latency_ms: None,
                detail: Some(format!(
                    "quarantine window of {}s elapsed",
                    self.cfg.cli.quarantine.as_secs()
                )),
                ts: crate::audit::now_ms(),
            });
        }

        // Re-evaluate whole-IP quarantines: expire them with the same window.
        let ip_window_ms = self.cfg.cli.quarantine.as_millis() as u64;
        let mut live_ips: Vec<(IpAddr, u64)> = Vec::new();
        for (ip, until) in &self.quarantined_ips_expiry {
            if now_ms < *until {
                live_ips.push((*ip, *until));
            } else {
                let mut plane = self.plane.lock().await;
                plane
                    .unblock_ip(&crate::protocol::IpKey::from_ip(*ip))
                    .ok();
                drop(plane);
                self.audit.lock().await.log(AuditEvent {
                    event: "ip_isolation_released",
                    level: "info",
                    flow: None,
                    src_ip: Some(*ip),
                    risk: None,
                    threshold: Some(self.ctrl.threshold),
                    confidence: None,
                    decision: Some(Decision::Unquarantine),
                    rationale: vec![],
                    action: Some(ActionRef {
                        kind: "unblock",
                        map: "blocklist_ip",
                        key: format!("{ip}"),
                        reason: "ttl_expired",
                        seq: 0,
                        ttl_ns: 0,
                    }),
                    latency_ms: None,
                    detail: Some(format!(
                        "IP quarantine window of {}s elapsed",
                        ip_window_ms / 1000
                    )),
                    ts: crate::audit::now_ms(),
                });
            }
        }
        self.quarantined_ips_expiry = live_ips;
    }

    async fn publish_metrics(&mut self) {
        let counters = self.plane.lock().await.snapshot_counters();
        let quarantined_flows = self
            .table
            .sessions
            .values()
            .filter(|s| s.state == SessionState::Quarantined)
            .count();
        let mut m = self.metrics.lock().await;
        m.pass = counters.pass;
        m.drop = counters.drop;
        m.block_hits = counters.block_hits;
        m.new_flows = counters.new_flows;
        m.malformed = counters.malformed;
        m.events_lost = counters.events_lost;
        m.sessions = self.table.sessions.len();
        m.quarantined_flows = quarantined_flows;
        m.quarantined_ips = self.quarantined_ips_expiry.len();
        m.decisions = self.decisions.load(std::sync::atomic::Ordering::Relaxed);
        m.enforce = self.enforce;
    }

    async fn toggle_enforce(&mut self) {
        self.enforce = !self.enforce;
        self.plane
            .lock()
            .await
            .apply_control(self.enforce, &self.cfg)
            .ok();
        self.audit.lock().await.log(AuditEvent {
            event: "mode_toggle",
            level: "info",
            flow: None,
            src_ip: None,
            risk: None,
            threshold: Some(self.ctrl.threshold),
            confidence: None,
            decision: Some(Decision::Monitor),
            rationale: vec![],
            action: Some(ActionRef {
                kind: "ctl",
                map: "ctl",
                key: "mode".into(),
                reason: if self.enforce { "enforce" } else { "monitor" },
                seq: 0,
                ttl_ns: 0,
            }),
            latency_ms: None,
            detail: Some(if self.enforce {
                "switched to enforce (drops active)".into()
            } else {
                "switched to monitor (observe only)".into()
            }),
            ts: crate::audit::now_ms(),
        });
        tracing::info!(enforce = self.enforce, "mode toggled via SIGUSR1");
    }

    async fn dump_table(&mut self) {
        let summary: Vec<_> = self
            .table
            .sessions
            .iter()
            .map(|(k, s)| {
                format!(
                    "{:?} {:?} {} -> {}:{} pkts={} risk={:.2}",
                    s.state,
                    crate::protocol::L7App::from_u8(s.l7_app),
                    k.src_ip(),
                    k.dst_ip(),
                    k.dport,
                    s.packets,
                    s.risk
                )
            })
            .collect();
        tracing::info!("session dump ({}):\n{}", summary.len(), summary.join("\n"));
        self.audit.lock().await.log(AuditEvent {
            event: "session_dump",
            level: "info",
            flow: None,
            src_ip: None,
            risk: None,
            threshold: None,
            confidence: None,
            decision: None,
            rationale: vec![],
            action: None,
            latency_ms: None,
            detail: Some(summary.join("\n")),
            ts: crate::audit::now_ms(),
        });
    }
}
