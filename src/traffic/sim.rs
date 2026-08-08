//! Synthetic traffic generator for `--mock` mode.
//!
//! Drives the same packet path the kernel probes would: updates the mock data
//! plane's flow metrics / counters via [`DataPlane::ingest_packet`] and emits
//! `NewFlow` events into the shared event channel, so the triage + quarantine
//! + audit pipeline runs end to end without root.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex, watch};
use tokio::time::sleep;

use crate::bpf::DataPlane;
use crate::protocol::{EventKind, FlowKey, KernelEvent, L7App};

/// CLOCK_BOOTTIME in nanoseconds, matching `pipeline::boot_ns()` so the mock
/// timestamps live in the same time domain as the triage rate calculations.
fn boottime_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid pointer to a timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortMode {
    Fixed,
    /// Step the destination port across a range (port-scan patterns).
    StepDstPort { from: u16, to: u16 },
}

#[derive(Clone, Copy, Debug)]
pub struct FlowSpec {
    #[allow(dead_code)]
    pub name: &'static str,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    /// TCP flags applied to every packet of the flow (0 for UDP/ICMP).
    pub flags: u8,
    pub l7: L7App,
    pub l7_info: u16,
    pub pps: f64,
    pub start_s: f64,
    pub duration_s: f64,
    pub pkt_len: u32,
    pub port_mode: PortMode,
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A few canonical scenarios: benign traffic, a port scanner, a SYN flood, DNS
/// tunneling, volumetric exfiltration and an internal lateral move.
pub fn scenarios() -> Vec<FlowSpec> {
    use PortMode::*;
    vec![
        FlowSpec {
            name: "benign-web",
            src: ipv4(10, 0, 0, 11),
            dst: ipv4(198, 51, 100, 20),
            sport: 50000,
            dport: 443,
            proto: 6,
            flags: 0x12, // established TCP (SYN|ACK)
            l7: L7App::Tls,
            l7_info: 0x0303,
            pps: 8.0,
            start_s: 0.0,
            duration_s: 90.0,
            pkt_len: 1400,
            port_mode: Fixed,
        },
        FlowSpec {
            name: "benign-dns",
            src: ipv4(10, 0, 0, 11),
            dst: ipv4(198, 51, 100, 53),
            sport: 5353,
            dport: 53,
            proto: 17,
            flags: 0,
            l7: L7App::Dns,
            l7_info: 14,
            pps: 2.0,
            start_s: 0.0,
            duration_s: 90.0,
            pkt_len: 512,
            port_mode: Fixed,
        },
        FlowSpec {
            name: "attacker-portscan",
            src: ipv4(198, 51, 100, 10),
            dst: ipv4(10, 0, 0, 5),
            sport: 44444,
            dport: 1,
            proto: 6,
            flags: 0x02, // SYN-only probes
            l7: L7App::UnknownTcp,
            l7_info: 0,
            pps: 5.0,
            start_s: 2.0,
            duration_s: 8.0,
            pkt_len: 60,
            port_mode: StepDstPort { from: 1, to: 1000 },
        },
        FlowSpec {
            name: "attacker-synflood",
            src: ipv4(198, 51, 100, 11),
            dst: ipv4(10, 0, 0, 5),
            sport: 33333,
            dport: 443,
            proto: 6,
            flags: 0x02, // SYN-only flood
            l7: L7App::UnknownTcp,
            l7_info: 0,
            pps: 120.0,
            start_s: 3.0,
            duration_s: 15.0,
            pkt_len: 60,
            port_mode: Fixed,
        },
        FlowSpec {
            name: "attacker-dnstunnel",
            src: ipv4(203, 0, 113, 7),
            dst: ipv4(10, 0, 0, 53),
            sport: 40000,
            dport: 53,
            proto: 17,
            flags: 0,
            l7: L7App::Dns,
            l7_info: 58,
            pps: 40.0,
            start_s: 5.0,
            duration_s: 30.0,
            pkt_len: 900,
            port_mode: Fixed,
        },
        FlowSpec {
            name: "attacker-exfil",
            src: ipv4(10, 0, 0, 12),
            dst: ipv4(203, 0, 113, 99),
            sport: 60000,
            dport: 5555,
            proto: 17,
            flags: 0,
            l7: L7App::UnknownUdp,
            l7_info: 0,
            pps: 1500.0,
            start_s: 8.0,
            duration_s: 12.0,
            pkt_len: 1500,
            port_mode: Fixed,
        },
        FlowSpec {
            name: "attacker-lateral",
            src: ipv4(10, 0, 0, 5),
            dst: ipv4(10, 0, 0, 20),
            sport: 51234,
            dport: 22,
            proto: 6,
            flags: 0x02, // SYN attempts to sensitive service
            l7: L7App::UnknownTcp,
            l7_info: 0,
            pps: 1.0,
            start_s: 12.0,
            duration_s: 30.0,
            pkt_len: 60,
            port_mode: Fixed,
        },
    ]
}

/// Continuously drive the mock plane until the attack scenarios have played
/// out, then stop.
pub async fn run_simulator(
    plane: Arc<Mutex<Box<dyn DataPlane + Send>>>,
    tx: mpsc::Sender<KernelEvent>,
    stop: watch::Receiver<bool>,
) {
    let specs = scenarios();
    let started = Instant::now();
    let base = boottime_ns();
    let mut fractional = vec![0.0f64; specs.len()];
    let mut next_port = vec![0u16; specs.len()];
    let mut seen = HashSet::new();

    loop {
        let now = started.elapsed().as_secs_f64();
        if *stop.borrow() || now > 90.0 {
            break;
        }

        for (i, spec) in specs.iter().enumerate() {
            let elapsed = now - spec.start_s;
            if elapsed < 0.0 || elapsed > spec.duration_s {
                continue;
            }
            fractional[i] += spec.pps * 0.1;
            let n = fractional[i] as u64;
            fractional[i] -= n as f64;
            if n == 0 {
                continue;
            }
            let mut plane = plane.lock().await;
            for _ in 0..n {
                let ts_ns = base + (now * 1e9) as u64;
                let key = make_key(spec, &mut next_port[i]);
                plane.ingest_packet(&key, spec.pkt_len, ts_ns, spec.flags);
                if seen.insert(key) {
                    let ev = KernelEvent {
                        kind: EventKind::NewFlow as u32,
                        ts_ns: (ts_ns & 0xFFFF_FFFF) as u32,
                        len: spec.pkt_len,
                        cpu: 0,
                        key,
                        l7_app: spec.l7 as u16,
                        l7_info: spec.l7_info,
                    };
                    let _ = tx.try_send(ev);
                }
            }
            drop(plane);
        }
        sleep(Duration::from_millis(100)).await;
    }
    tracing::info!("simulator finished (all scenarios played)");
}

fn make_key(spec: &FlowSpec, next_port: &mut u16) -> FlowKey {
    let mut key = FlowKey::default();
    key.proto = spec.proto;
    match (spec.src, spec.dst) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            key.saddr[0] = u32::from_be_bytes(a.octets());
            key.daddr[0] = u32::from_be_bytes(b.octets());
        }
        _ => {}
    }
    key.sport = spec.sport;
    key.dport = match spec.port_mode {
        PortMode::Fixed => spec.dport,
        PortMode::StepDstPort { from, to } => {
            let d = from + (*next_port % (to - from));
            *next_port = next_port.wrapping_add(1);
            d
        }
    };
    key
}
