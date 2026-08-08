# eBPF Agentic Firewall

An eBPF-driven zero-trust quarantine controller. XDP/TC probes observe every
flow at line rate and push compact per-flow metrics into a ring buffer; a Rust
daemon aggregates them, runs a transparent multi-signal risk triage, and when a
flow crosses a configurable threshold it writes a time-bounded blocklist entry
back into the kernel maps. The isolation is applied in the kernel within
microseconds of a decision and automatically reverts when the quarantine window
expires.

The whole thing is testable without root: `--mock` drives the exact same packet
path with a synthetic traffic generator so the triage → quarantine → audit
pipeline runs end to end on any machine.

## Architecture

```
                        userspace                       kernel
┌──────────────────────────────────────────────────┐  ┌───────────────────────┐
│  zqfw (Rust daemon)                              │  │  firewall.bpf.c       │
│                                                  │  │                       │
│  supervisor ── every --reap-interval ────────────┼─▶│  XDP/TC hook          │
│    · merge flow metrics from ring buffer         │  │   · classify L7       │
│    · rebuild triage context (1-2 min windows)    │  │   · lookup blocklist  │
│    · score each session with signal weights      │  │   · drop or pass      │
│    · write blocklist / blocklist_ip on decision  │  │   · ring-buffer event │
│    · expire quarantines back to allow            │  │                       │
│                                                  │  │  blocklist (LRU map)  │
│  LLM review (--features llm, optional)           │  │  blocklist_ip         │
│    · free-form second opinion on risk ≥ 0.5      │  │  ctl (enforce flag)   │
│                                                  │  │  counters             │
│  audit: JSONL with rationale & decision latency  │  └───────────────────────┘
│  metrics: Prometheus on --metrics-addr           │
└──────────────────────────────────────────────────┘
```

* **Data plane** (`bpf/`, `src/bpf.rs`): XDP and TC programs classify traffic,
  maintain per-flow metrics (`flow` map) and apply the blocklists. The control
  plane (`ctl` map, enforce flag) lets the daemon switch between *monitor*
  (observe only) and *enforce* (drop) modes at runtime.
* **Triage** (`src/triage/`): each session is scored by a set of independent
  signals, each producing `(contribution, evidence)` with a fixed weight.
  `risk = Σ(contribution·weight) / Σ(weight over fired signals)`.
* **Controller** (`src/pipeline.rs`): a `Supervisor` task owns the event loop,
  the session table and the quarantine lifecycle, and writes decisions back to
  the kernel with sub-millisecond latency.

### Signals

| signal            | weight | fires on |
|-------------------|--------|----------|
| `port_scan`       | 0.9    | ≥ 10 distinct dst ports (or ≥ 20 distinct dst IPs) from one src |
| `syn_flood`       | 0.95   | high SYN rate, or many SYNs with no ACK observed |
| `dns_tunnel`      | 0.85   | DNS with abnormally long query names at volume |
| `data_exfil`      | 0.9    | high byte-rate to an unusual port (raw or encrypted) |
| `unidirectional_udp` | 0.6 | UDP burst with no response traffic |
| `lateral_movement` | 0.95  | internal→internal SYN attempts to sensitive services |
| `first_contact`   | 0.3    | a public source seen for the first time in the window |
| `rst_flood`, `slow_drip` | 0.8 / 0.5 | RST storms; long-lived low-rate flows |

### Decisions

* `Allow` – risk below threshold (default 0.8). Flow proceeds.
* `Monitor` – not enough evidence yet; session is tracked as *suspicious*.
* `Quarantine` – block the specific 5-tuple in `blocklist` for `--quarantine`.
* `QuarantineIp` – with `--block-ip`, systemic behaviour (e.g. port scan) also
  blocks the whole source IP in `blocklist_ip`; the reverse direction of the
  session is blocked too (zero-trust).

Every isolation is TTL-bounded and reverted automatically. Sessions whose
source is already IP-quarantined are skipped to avoid log spam.

## Quickstart

Prerequisites: a recent `clang` + `llvm-strip` (to compile the eBPF program),
Rust stable, and `libbpf` headers for real mode. On Debian/Ubuntu:

```sh
apt install clang llvm libbpf-dev libelf-dev
```

### 1. Try it without root (synthetic traffic)

```sh
cargo build --release
./target/release/zqfw --mock --block-ip --audit audit.jsonl
```

This drives ~90 s of benign and attack traffic (port scan, SYN flood, DNS
tunneling, data exfiltration, internal lateral movement) through the real
triage pipeline. Watch the decisions land in `audit.jsonl`:

```sh
tail -f audit.jsonl            # each line is a JSON audit event
grep isolation_enforced audit.jsonl
```

Each enforcement includes the decision, risk score, the signals that fired with
their evidence, the enforced map/key, the quarantine TTL, and the end-to-end
decision latency (typically microseconds):

```json
{"level":"alert","event":"isolation_enforced","flow":{"src":"203.0.113.7:40000","dst":"10.0.0.53:53","proto":"udp","app":"dns"},"src_ip":"203.0.113.7","risk":1.0,"decision":"quarantine","rationale":[{"signal":"dns_tunnel","contribution":1.0,"evidence":"DNS tunneling: ..."}],"action":{"kind":"flow_quarantine","map":"blocklist","key":"203.0.113.7:40000->10.0.0.53:53","reason":"triage","ttl_ns":300000000000},"latency_ms":0.004}
```

### 2. Real mode (needs root + a kernel with BTF)

```sh
sudo ./target/release/zqfw --iface eth0 --block-ip --monitor
```

Start in `--monitor` mode to observe decisions without dropping anything, then
flip to enforce at runtime:

```sh
sudo kill -USR1 $(pgrep zqfw)    # toggle monitor ↔ enforce
sudo kill -USR2 $(pgrep zqfw)    # dump the live session table
```

## CLI

```
--iface <IFACE>           interface to attach XDP/TC probes to (real mode) [lo]
--mock                    run without kernel access (synthetic traffic)
--xdp-mode <mode>         default | skb | driver
--monitor                 start in monitor mode; SIGUSR1 toggles enforce
--threshold <0..1>        risk threshold for quarantine (default 0.8)
--quarantine <dur>        quarantine TTL (default 5m)
--reap-interval <dur>     re-evaluation / reaper interval (default 5s)
--flow-ttl <dur>          idle flow expiry (default 60s)
--block-ip                also quarantine whole source IPs on systemic behaviour
--hit-events              emit block-hit events into the ring buffer
--audit <path>            JSONL audit log; "-" for stdout (default -)
--metrics-addr <addr>     Prometheus metrics bind address (default 127.0.0.1:9790)
--pin-dir <dir>           directory where pinned BPF maps live (troubleshooting)
```

## Metrics

Prometheus text exposition on `--metrics-addr`:

* `zqfw_packets_passed_total`, `zqfw_packets_dropped_total`, `zqfw_block_hits_total`
* `zqfw_new_flows_total`, `zqfw_malformed_total`, `zqfw_events_lost_total`
* `zqfw_sessions`, `zqfw_quarantined_flows`, `zqfw_quarantined_ips`
* `zqfw_decisions_total`, `zqfw_enforce`

## Audit events

* `supervisor_started` – startup configuration
* `isolation_enforced` – a decision was written to the kernel (alert)
* `isolation_released` / `ip_isolation_released` – TTL expired, allow restored
* `llm_rationale` – free-form LLM second opinion (with `--features llm`)
* `mode_toggle` / `session_dump` – control-plane events

## Layout

```
bpf/                     eBPF C source (XDP/TC probes) + vendored headers
src/
  bpf.rs                 DataPlane abstraction, aya map/program loading
  mock.rs                in-process mock plane for --mock mode
  traffic/sim.rs         synthetic attack/benign scenario generator
  flow.rs                session table (merge, state machine, TTL)
  triage/                signal registry, context, risk aggregation
  pipeline.rs            Supervisor: event loop, decisions, quarantine lifecycle
  audit.rs               structured JSONL audit logger
  metrics.rs             Prometheus exporter
  config.rs              CLI + config
main.rs                  wiring, signal handling
docs/README.md           this file
```

## Tests

```sh
cargo test       # protocol round-trips, triage decisions, BPF object parse
```

The triage unit tests assert the exact behaviours the mock scenario relies on:
benign traffic stays `Allow`, a SYN flood is quarantined, and a multi-host port
scan escalates to an IP quarantine when `--block-ip` is enabled.
