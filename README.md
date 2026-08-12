<div align="center">

# 🛡️ Protector (zqfw)
### eBPF-driven zero-trust quarantine firewall

*Kernel-speed detection, kernel-speed enforcement, and automatic self-healing — all in one Rust + eBPF daemon.*

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/eBPF-XDP%20%2B%20TC-blue.svg)](https://ebpf.io/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Tests](https://img.shields.io/badge/tests-10%2F10%20passing-brightgreen.svg)](RESULTS.md)

</div>

---

## What is this?

**Protector** (binary name `zqfw`) is an **agentic eBPF firewall**. Kernel probes
(XDP + TC) inspect every packet at line rate and mirror lightweight per-flow
metrics to userspace. A Rust triage daemon scores each session against eight
transparent, weighted evidence signals, and when a flow crosses the risk
threshold it writes a block entry straight into the kernel's BPF maps —
**enforcement lands in under a millisecond**. Quarantines are TTL-bounded, so
a host that stops behaving badly is automatically un-blocked without any
human in the loop.

Verified live on kernel 6.19 (see [`RESULTS.md`](RESULTS.md)): a live port
scan was detected and quarantined within one reap interval, with **0.9–21 µs**
enforcement latency and in-kernel drop counters confirmed 1:1 against
`block_hits`.

## Table of contents

- [Highlights](#highlights)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Advanced features](#advanced-features)
- [Tuning reference](#tuning-reference)
- [Metrics & observability](#metrics--observability)
- [Testing](#testing)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

## Highlights

- **Kernel data plane (XDP + TC)** — per-flow metrics, light L7
  classification, and blocklist enforcement, with zero userspace round-trip
  on the hot path.
- **Transparent triage** — eight weighted signals (`port_scan`, `syn_flood`,
  `dns_tunnel`, `data_exfil`, `lateral_movement`, `first_contact`, `rst_flood`,
  `slow_drip`) score every session; every decision is fully auditable.
- **Zero-trust, self-healing lifecycle** — quarantines are TTL-bounded and
  idempotent. A blocked host recovers automatically once the evidence clears.
- **Monitor-first workflow** — attach in monitor mode, review the audit log,
  then flip to enforcement live with `SIGUSR1`. No restart, no rule reload.
- **Rootless demo** — `--mock` replays the exact same pipeline against a
  synthetic traffic generator, so you can try it without `sudo`.
- **Production-minded ops** — Prometheus metrics, JSONL audit log, optional
  LLM second opinion, systemd hardening, allowlisting, and fail-closed
  behavior on restart/shutdown (see [Advanced features](#advanced-features)).

## How it works

```
                        userspace                          kernel
┌───────────────────────────────────────────┐  ┌───────────────────────┐
│  zqfw (Rust daemon)                               │  │  firewall.bpf.c       │
│                                                    │  │                       │
│  supervisor ── every --reap-interval ────────────┼▶│  XDP (ingress)        │
│    · merge flow metrics from ring buffer          │  │  TC (in/egress)       │
│    · rebuild triage context (1-2 min windows)     │  │   · parse L2-L4       │
│    · score sessions: risk = Σ(w·c) / Σ(w)         │  │   · L7 classification │
│    · write blocklist / blocklist_ip on decision   │◀─┼── blocklist lookups   │
│    · expire quarantines back to allow (TTL)       │  │   · drop / pass       │
│                                                    │  │   · ring-buffer event │
│  audit: JSONL, rationale + latency per decision    │  │                       │
│  metrics: Prometheus on --metrics-addr             │  │  maps: flows,         │
│  LLM review (--features llm, optional)            │  │  blocklist,           │
└───────────────────────────────────────────┘  │  blocklist_ip, ctl,   │
                                                        │  counters, allowlist  │
                                                        └─────────────────────┘
```

**Signals and weights:**

| signal | weight | fires on |
|---|---|---|
| `port_scan` | 0.90 | ≥10 distinct dst ports or ≥20 distinct dst IPs from one source |
| `syn_flood` | 0.95 | high SYN rate, or many SYNs with no matching ACK |
| `dns_tunnel` | 0.85 | high-volume DNS with abnormally long query names |
| `data_exfil` | 0.90 | high byte rate to an unusual port |
| `unidirectional_udp` | 0.60 | UDP burst with no response traffic |
| `lateral_movement` | 0.95 | internal→internal SYNs to sensitive services |
| `first_contact` | 0.30 | a public source seen for the first time in the window |
| `rst_flood` / `slow_drip` | 0.80 / 0.50 | RST storms; long-lived low-rate flows |

`risk = Σ(contribution · weight) / Σ(weight of fired signals)` — a
reproducible score, not a black box. Decisions: `Allow`, `Monitor`,
`Quarantine` (single 5-tuple), or `QuarantineIp` (systemic behaviour, blocks
the whole source).

## Requirements

- **Linux 5.8+** (BTF support recommended) with a NIC you can attach XDP to.
- **Root** (or `CAP_BPF` + `CAP_NET_ADMIN`) to load BPF objects in real mode.
  Mock mode needs neither.
- **clang/LLVM** to compile the C probes, a **Rust toolchain**, `libelf`, and
  optionally `linux-headers-$(uname -r)`.
- For BPF map persistence: `bpftool` and a mounted BPF filesystem
  (`mount -t bpf bpf /sys/fs/bpf`).

## Install

### One-shot script (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine + derivatives)

```bash
git clone https://github.com/blah-blah-cell/protector.git
cd protector
./scripts/install.sh            # installs deps, builds, installs to /usr/local/bin
zqfw --version                  # verify
```

You'll be prompted for your `sudo` password once or twice — that's expected.

### Manual (any distro)

```bash
# 1. Toolchain
rustup 2>/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install -y clang llvm libelf-dev linux-tools-common   # Debian/Ubuntu
sudo dnf install -y clang llvm elfutils-libelf-devel            # Fedora
sudo pacman -Sy --noconfirm base-devel clang llvm elfutils      # Arch

# 2. Build
cargo build --release                       # default: monitor-first triage
cargo build --release --features llm        # + optional LLM review backend

# 3. Install
sudo install -m 0755 target/release/zqfw /usr/local/bin/zqfw
```

### Run as a service (systemd)

```bash
sudo install -m 0644 packaging/zqfw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zqfw    # attaches to the default-route NIC, monitor-first
sudo journalctl -fu zqfw
```

## Usage

### Rootless demo (no BPF, no root)

```bash
zqfw --mock --block-ip --audit audit.jsonl
```

Runs a simulated network with five attack scenarios — port scan, SYN flood,
DNS tunneling, exfiltration, lateral movement — and prints each enforced
quarantine with its evidence, risk score, and latency.

### Real mode (attach to live traffic)

```bash
sudo zqfw --iface eth0 --block-ip --monitor --reap-interval 2s --quarantine 30s
```

- `--iface` defaults to **`auto`** (the default-route interface): `eth0`,
  `enp0s3`, `ens33`, `wlan0`, etc. are all auto-detected. Force one with
  `--iface ens33` or `ZQFW_IFACE=ens33`.
- `--monitor` observes and logs but **never blocks**. When ready, toggle
  enforcement live — no restart required:
  ```bash
  sudo kill -USR1 "$(pgrep zqfw)"   # toggle monitor ↔ enforce
  sudo kill -USR2 "$(pgrep zqfw)"   # dump the live session table
  ```

## Advanced features

### Allowlist trusted sources

Exempt trusted CIDRs (management networks, DNS servers, etc.) from quarantine
entirely — they bypass enforcement at the kernel level, before triage even
runs:

```bash
sudo zqfw --iface auto --block-ip --allowlist 10.0.0.0/8,192.168.1.0/24
```

Accepts CIDR notation and exact IPs (`/32`, `/128`). Prefixes that would
expand past 65,536 addresses are skipped with a warning to avoid resource
exhaustion.

### BPF map persistence (fail-closed across restarts)

Pin BPF maps to the filesystem so active quarantines survive a daemon
restart:

```bash
sudo mount -t bpf bpf /sys/fs/bpf   # once at boot
sudo zqfw --pin-dir /sys/fs/bpf/zqfw ...
```

Maps are pinned under `/sys/fs/bpf/zqfw/` (`flows`, `blocklist`,
`blocklist_ip`, `allowlist`, `ctl`, `counters`). On restart the daemon reuses
the pinned maps instead of starting from empty state.

### Fail-closed on shutdown

On `SIGTERM`, the daemon stops its own control loop but **leaves the eBPF
probes attached**, so any active quarantines keep being enforced by the
kernel until the process is fully reaped or the host reboots:

```bash
sudo kill -TERM "$(pgrep zqfw)"   # triggers fail-closed shutdown
```

### Systemd hardening

`packaging/zqfw.service` ships with:

- `Type=notify` + systemd watchdog (`WatchdogSec=30`, `sd_notify` heartbeat).
- `Restart=always` with `StartLimitBurst=3`.
- A minimal capability set (`CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
  `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`) instead of unrestricted root.
- Filesystem protection (`ProtectSystem=strict`, `ProtectHome=true`,
  `PrivateTmp=true`) and syscall filtering
  (`@system-service @clock @network @bpf @resources @file-system`).
- Resource limits (`LimitNOFILE=65536`, `LimitMEMLOCK=infinity`,
  `MemoryMax=512M`).
- Config overrides via `EnvironmentFile=/etc/default/zqfw` — see
  `packaging/zqfw.env` for the full list of variables.

## Tuning reference

| flag | default | meaning |
|---|---|---|
| `--threshold` | 0.8 | risk score needed to quarantine (0–1) |
| `--quarantine` | 5m | how long a blocked IP/flow stays blocked, e.g. `30s`, `5m` |
| `--reap-interval` | 5s | supervisor re-evaluation period |
| `--flow-ttl` | 60s | idle flow expiry |
| `--monitor` | off | never drop — observe/audit only |
| `--block-ip` | off | whole-IP quarantines on systemic behaviour (port scan) |
| `--allowlist` | none | comma-separated CIDRs exempt from quarantine |
| `--pin-dir` | none | directory to pin BPF maps for fail-closed persistence |
| `--metrics-addr` | 127.0.0.1:9790 | Prometheus text endpoint |
| `--audit` | `-` | JSONL audit path (`-` for stdout) |
| `--hit-events` | off | emit block-hit events into the ring buffer |
| `--xdp-mode` | default | `default` \| `skb` \| `driver` |

## Metrics & observability

- **Audit** (`--audit audit.jsonl`) — every decision with risk, signals,
  weights, confidence, latency, and the exact kernel map written.
- **Prometheus** — `curl localhost:9790/metrics` exposes
  `zqfw_packets_passed_total`, `zqfw_packets_dropped_total`,
  `zqfw_block_hits_total`, `zqfw_quarantined_ips`, `zqfw_sessions`, and more.
- **Signals** — `SIGUSR1` toggles monitor/enforce, `SIGUSR2` dumps the live
  session table.

## Testing

```bash
cargo test          # 10 unit + regression tests: byte-order, triage, BPF object parse, mock e2e
```

Live-system verification and the seven bugs found and fixed during real-mode
testing are documented in [`RESULTS.md`](RESULTS.md#4-bugs-found-and-fixed-during-real-mode-testing).

## FAQ

**Does it really enforce, or is it just monitoring?**
It really enforces. Once monitor mode is toggled off (`SIGUSR1`), the probes
drop packets in the kernel. Undetected flows pass; quarantined flows/IPs are
dropped with a counter increment read back from the kernel map.

**Will it block my own traffic?**
On a live host, first contact with a new destination can look suspicious (the
`first_contact` signal alone can reach the default 0.8 threshold). Run
`--monitor` first, review the audit log, and consider `--allowlist` for
known-good sources before enforcing.

**Why does it need root?**
Loading eBPF requires `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`. The rootless
`--mock` demo needs none of that.

## Disclaimer

This tool blocks real network traffic and **can break connectivity** if
misconfigured or confused by traffic it should ignore. Always run in
`--monitor` mode first and treat the audit log as the source of truth before
switching to enforcement.

## License

MIT
