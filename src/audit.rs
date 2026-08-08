//! Structured audit logging.
//!
//! Every isolation decision is recorded as a single JSON line containing the
//! decision, the risk, the *rationale* (which signals fired, with weights and
//! evidence), and the resulting enforcement action taken against the kernel
//! data plane (map update latency included).

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::protocol::{FlowKey, L7App};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Quarantine,
    QuarantineIp,
    Monitor,
    Allow,
    Unquarantine,
    #[allow(dead_code)]
    Expire,
}

#[derive(Debug, Clone, Serialize)]
pub struct RationaleSignal {
    pub signal: &'static str,
    pub weight: f64,
    pub contribution: f64,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub ts: u64,
    pub level: &'static str,
    pub event: &'static str,
    pub flow: Option<FlowRef>,
    pub src_ip: Option<IpAddr>,
    pub risk: Option<f64>,
    pub threshold: Option<f64>,
    pub confidence: Option<f64>,
    pub decision: Option<Decision>,
    pub rationale: Vec<RationaleSignal>,
    pub action: Option<ActionRef>,
    pub latency_ms: Option<f64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRef {
    pub src: String,
    pub dst: String,
    pub proto: &'static str,
    pub app: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionRef {
    pub kind: &'static str,
    pub map: &'static str,
    pub key: String,
    pub reason: &'static str,
    pub seq: u64,
    pub ttl_ns: u64,
}

impl FlowRef {
    pub fn from_key(key: &FlowKey, packets: u64, bytes: u64) -> Self {
        let proto = match key.proto {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            58 => "icmpv6",
            _ => "other",
        };
        FlowRef {
            src: format!("{}:{}", key.src_ip(), key.sport),
            dst: format!("{}:{}", key.dst_ip(), key.dport),
            proto,
            app: L7App::from_u8(0).name(), // filled in by callers when known
            packets,
            bytes,
        }
    }
}

pub struct AuditLogger {
    sink: Box<dyn Write + Send>,
    seq: std::sync::atomic::AtomicU64,
}

impl AuditLogger {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let sink: Box<dyn Write + Send> = if path == "-" {
            Box::new(io::stdout())
        } else {
            Box::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(Path::new(path))?,
            )
        };
        Ok(AuditLogger {
            sink,
            seq: Default::default(),
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn log(&mut self, mut ev: AuditEvent) {
        if ev.ts == 0 {
            ev.ts = now_ms();
        }
        let line = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into());
        let _ = writeln!(self.sink, "{line}");
        let _ = self.sink.flush();
    }

    #[allow(dead_code)]
    pub fn decision(&mut self, ev: AuditEvent) {
        let mut ev = ev;
        ev.level = "info";
        ev.event = "decision";
        self.log(ev);
    }

    pub fn enforce(&mut self, ev: AuditEvent) {
        let mut ev = ev;
        ev.level = "alert";
        ev.event = "isolation_enforced";
        self.log(ev);
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
