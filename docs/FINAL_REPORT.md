# Final Report — eBPF Agentic Firewall (zqfw)

A zero-trust quarantine controller: eBPF probes classify every flow at line
rate, a Rust triage daemon scores suspicious behaviour with a transparent
weighted-signal model, and decisions are enforced in the kernel within
microseconds — then automatically reverted when the quarantine window expires.

Verified live on kernel 6.19 (Kali) against real traffic. All evidence in
`RESULTS.md`; operational details in `docs/README.md`.

---

## 1. Problem & approach

Traditional firewalls match static rules; AI “security” products decide in the
cloud and cannot stop a first packet. This project takes the opposite shape:
**decide in the control plane, enforce in the data plane, revert by default.**

- The kernel does what kernels do well: inspect every packet, track per-flow
  metrics, and drop the exact flows/IPs the controller marks — with no
  userspace round-trip on the hot path.
- Userspace does what userspace does well: aggregate, reason with evidence,
  and decide. Decisions are TTL-bounded and self-healing.
- Every decision is auditable: the risk score, the signals that fired, the
  evidence text, the map written, and the enforcement latency.

## 2. Architecture

```
                 userspace                          kernel
┌──────────────────────────────────────────────┐  ┌─────────────────────────┐
│  zqfw (Rust daemon)                          │  │  firewall.bpf.c         │
│                                              │  │                         │
│  supervisor ── reap interval (2-5s) ─────────┼─▶│  XDP (ingress)          │
│   · merge flow metrics from ring buffer      │  │  TC (in/egress)         │
│   · rebuild 60s triage context               │  │   · parse L2-L4, L7 cls │
│   · score sessions (8 weighted signals)      │  │   · blocklist lookups   │
│   · write blocklist/blocklist_ip maps        │  │   · drop / pass         │
│   · expire quarantines (TTL)                 │  │   · ring-buffer events  │
│  audit JSONL · Prometheus metrics            │  │  maps: flows, blocklist,│
│  SIGUSR1 toggle · SIGUSR2 session dump       │  │  blocklist_ip, events, │
│  optional LLM review (--features llm)        │  │  ctl, counters          │
└──────────────────────────────────────────────┘  └─────────────────────────┘
```

### Data plane (kernel, `bpf/firewall.bpf.c`)

- **XDP** ingress + **TC** ingress/egress so both directions of every flow are
  seen and enforced at the earliest point.
- Per-flow metrics (packets, bytes, SYN/FIN/RST counts, TCP flags, L7 app
  probe) accumulate in the `flows` LRU map; new flows emit a ring-buffer event.
- Enforcement order: exact 5-tuple `blocklist`, then whole-source `blocklist_ip`
  (enabled with `--block-ip`). A `ctl` map holds the enforce flag so the daemon
  can switch monitor ↔ enforce without reloading programs.

### Triage (userspace, `src/triage/`)

Independent signals, each contributing evidence with a fixed weight:

| signal | weight | fires on |
|---|---|---|
| `port_scan` | 0.9 | ≥10 distinct dst ports / ≥20 dst IPs from one src |
| `syn_flood` | 0.95 | high SYN rate or many SYNs with no ACK observed |
| `dns_tunnel` | 0.85 | high volume of DNS with abnormally long query names |
| `data_exfil` | 0.9 | high byte rate to an unusual port (raw or encrypted) |
| `unidirectional_udp` | 0.6 | UDP burst with no response traffic |
| `lateral_movement` | 0.95 | internal→internal SYN attempts to sensitive services |
| `first_contact` | 0.3 | public source seen for the first time in the window |
| `rst_flood` / `slow_drip` | 0.8 / 0.5 | RST storms; low-and-slow flows |

`risk = Σ(contribution·weight) / Σ(weight of fired signals)` — a transparent,
reproducible score, not a black box. Decisions: `Allow` (below threshold),
`Monitor` (marked suspicious, tracked), `Quarantine` (5-tuple), `QuarantineIp`
(systemic behaviour, e.g. port scan → block the whole source).

### Enforcement loop (userspace, `src/pipeline.rs`)

A `Supervisor` task: merge kernel flow metrics → rebuild context → score
candidates (skipping already-quarantined sources) → write the block entry to
the kernel map (the sub-ms isolation step) → audit with rationale and latency →
expire TTLs back to allow. The reverse direction of an isolated session is
blocked too (zero-trust). Blocking is idempotent: one audit per IP per window.

### Observability

- **Audit**: JSONL with event, flow, risk, threshold, confidence, decision,
  rationale (signal + weight + contribution + evidence), action (map/key/
  reason/ttl), and `latency_ms`.
- **Metrics**: Prometheus text on `--metrics-addr` (passed/dropped/block_hits/
  new_flows/malformed/events_lost/sessions/quarantined_*/decisions/enforce).
- **Control**: SIGUSR1 toggles enforce↔monitor, SIGUSR2 dumps the session
  table.

### Mock mode

`--mock` swaps the BPF plane for an in-process fake and drives a deterministic
synthetic scenario (benign traffic + port scan, SYN flood, DNS tunnel,
exfiltration, lateral movement) through the **exact same** pipeline — the
full demo/tests run without root.

## 3. Verification

### Unit tests — 8/8 pass
Protocol round-trips (IPv4/IPv6 key layout), triage decisions (benign→Allow,
SYN flood→Quarantine, scan→QuarantineIp), BPF object parse.

### Mock end-to-end — all 5 attacks detected, 1–13 µs decisions

| attack | decision | signals | risk |
|---|---|---|---|
| port scan | `quarantine_ip` | port_scan, syn_flood | 1.0 |
| SYN flood | `quarantine` | syn_flood | 1.0 |
| DNS tunnel | `quarantine` | dns_tunnel | 1.0 |
| data exfiltration | `quarantine` | data_exfil, unidirectional_udp | 0.9 |
| lateral movement | `quarantine` | lateral_movement | 1.0 |

Plus: TTL release/self-heal cycles, IP-quarantine dedup, SIGUSR1/SIGUSR2.

### Real mode — live on eth0 (Kali 6.19, virtio NIC)

- Probes attached (XDP default mode + TC), verifier accepted both programs.
- A live `hping3 -S -p 1-100` scan of the LAN gateway was detected within one
  reap interval: `quarantine_ip` on the scanner's IP, risk 1.0, **0.9–21 µs**
  enforcement latency.
- After toggle to enforce: `ping` went from 2 ms RTT to **100% loss** and the
  kernel counters `dropped_total`/`block_hits_total` tracked blocked packets
  1:1 (0 → 34), read back from the map.
- TTL lifecycle confirmed in the audit: enforce → `ip_isolation_released
  ttl_expired` → re-enforce only while evidence persists.

## 4. Bugs found & fixed (all with live evidence)

1. **Reversed IPs (userspace)** — `to_be()` in `src_ip()`/`dst_ip()` produced
   `7.113.0.203` for `203.0.113.7`. Removed; round-trip tests added.
2. **Reversed IPs (kernel)** — probes stored raw network-order bytes in
   `saddr[]/daddr[]`; on little-endian hosts the daemon saw `250.31.168.192`.
   Fixed with `bpf_ntohl()` (IPv4 and per-u32 IPv6).
3. **Counters silently dead** — the `counters` map is a 1-entry array but the C
   code looked up indices 1/3/4 → out-of-range → NULL → `drop`/`new_flows`/
   `malformed` never incremented. All lookups now use index 0.
4. **`block_hits` never incremented** anywhere in the C source. Now bumped on
   both blocklist-hit paths alongside `drop`.
5. **Mock never tracked TCP flags** — hardcoded `tcp_flags_or = 0x12`, so
   `syn_flood`/`rst_flood` could not fire in mock mode. Per-flow `flags` are
   now threaded through the simulator.
6. **32-bit ns timestamps** — `first_seen_ns`/`last_seen_ns` as `u32` wrap
   every 4.3 s and truncated boottime values, corrupting all rate signals.
   Promoted to `u64` in the wire struct and C mirror.
7. **Time-domain mismatch in mock** — flow-relative mock timestamps vs
   boottime-based triage made byte rates meaningless. The simulator now emits
   `CLOCK_BOOTTIME`-based absolute timestamps.

## 5. Operational notes & known limitations

- **Zero-trust can be aggressive on a live host**: a host's own first contact
  with a public endpoint fires `first_contact` at exactly the threshold, and
  SYN-retransmit patterns can re-trigger quarantines. Deploy **monitor-first**
  (default flag), then toggle; consider allow-listing.
- XDP driver mode may be unavailable on some NICs/virtualisation — fall back
  with `--xdp-mode skb`.
- Under heavy scans the ring buffer drops new-flow events (counted in
  `events_lost`); decisions are unaffected because they run off the flow map
  snapshot.
- LLM review (`--features llm`, OpenAI-compatible HTTP) is wired for flows
  with risk ≥ 0.5 but was not exercised in these tests (no endpoint).

## 6. Repository map

```
bpf/firewall.bpf.c        XDP/TC probes, maps, L7 classification
src/bpf.rs                aya loading/attach, DataPlane abstraction
src/mock.rs               in-process fake plane (--mock)
src/traffic/sim.rs        synthetic attack/benign scenarios
src/triage/               signals, context, risk aggregation
src/pipeline.rs           supervisor: decisions, quarantine lifecycle
src/audit.rs, metrics.rs  JSONL audit, Prometheus exporter
docs/README.md            architecture + quickstart
RESULTS.md                test evidence and bug log
```

## 7. Quick start

```sh
cargo build --release && cargo test

# no root needed
./target/release/zqfw --mock --block-ip --audit audit.jsonl

# real (root)
sudo ./target/release/zqfw --iface eth0 --block-ip --monitor \
     --reap-interval 2s --quarantine 30s
sudo kill -USR1 $(pgrep zqfw)      # toggle enforce
```
