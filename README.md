# Protector — eBPF zero-trust quarantine firewall

An **agentic eBPF firewall**: kernel probes inspect every packet at line rate,
a Rust triage daemon scores suspicious traffic with transparent weighted
evidence, blocks it in-kernel in **<1 ms**, then automatically reverts when the
quarantine window expires (self-healing).

* **Kernel data plane** (XDP + TC): per-flow metrics, L7 classification,
  blocklist enforcement — zero userspace hot path.
* **Transparent triage**: 8 weighted signals (`port_scan`, `syn_flood`,
  `dns_tunnel`, `data_exfil`, `lateral_movement`, `first_contact`, ...) score
  every session; every decision is auditable (JSONL audit log).
* **Zero-trust lifecycle**: quarantines are TTL-bounded and idempotent;
  blocked hosts recover automatically when the evidence clears.
* **Monitor-first**: attach in monitor mode, review, toggle enforce live with
  SIGUSR1 — no restart, no rule reload.
* **Prometheus metrics** + JSONL audit + LLM review (optional `--features llm`).
* **Rootless demo**: `--mock` runs the identical pipeline on a synthetic
  traffic generator without sudo.

Verified live on kernel 6.19 (`RESULTS.md`): scanned host quarantined in one
sweep, enforcement latency **0.9–21 µs**, in-kernel drops confirmed 1:1 with
`block_hits`.

---

## Requirements

* **Linux 5.8+** (BFT/BTF support recommended) with a NIC you can attach XDP to.
* **Root** (or `CAP_BPF + CAP_NET_ADMIN`) to load the BPF objects in real mode.
  Mock mode needs neither.
* **clang/LLVM** (to compile the C probes), a **Rust toolchain**, `libelf`,
  and optionally `linux-headers-$(uname -r)`.

## Install

### One-shot script (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine + derivatives)

```bash
git clone https://github.com/blah-blah-cell/protector.git
cd protector
./scripts/install.sh            # installs deps, builds, installs to /usr/local/bin
```

You will be prompted for your `sudo` password once or twice — completely normal.
Verify:

```bash
zqfw --version
```

### Manual (any distro)

```bash
# 1. Toolchain
cargo install cargo-bpf-maintainer  # not needed; just:
rustup 2>/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install -y clang llvm libelf-dev linux-tools-common  # Debian/Ubuntu
sudo dnf install -y clang llvm elfutils-libelf-devel          # Fedora
sudo pacman -Sy --noconfirm base-devel clang llvm elfutils    # Arch

# 2. Build
cargo build --release                      # default = monitor-first triage
cargo build --release --features llm        # + optional LLM review backend

# 3. Install
sudo install -m 0755 target/release/zqfw /usr/local/bin/zqfw
```

### Service (systemd)

```bash
sudo mkdir -p /var/log/zqfw 2>/dev/null; :
sudo install -m 0644 packaging/zqfw.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now zqfw          # attaches to your default-route NIC, monitors
sudo journalctl -fu zqfw
```

## Usage

### Rootless demo (no BPF, no root)

```bash
zqfw --mock --block-ip --audit audit.jsonl
```

Runs a simulated network with 5 attack scenarios (port scan, SYN flood,
DNS tunneling, exfiltration, lateral movement) and shows each enforced
quarantine with its evidence, risk score, and latency.

### Real mode (attach to live traffic)

```bash
sudo zqfw --iface eth0 --block-ip --monitor --reap-interval 2s --quarantine 30s
```

* `--iface` defaults to **`auto`** (the default-route interface) — on this PMC,
  eth0, enp0s3, ens33, wlan0 etc. are all auto-detected. To force: `--iface ens33`
  or set `ZQFW_IFACE=ens33`.
* `--monitor` observes and logs but **never blocks**. When you are ready,
  toggle enforcement live:
  ```bash
  sudo kill -USR1 "$(pgrep zqfw)"   # toggle monitor ↔ enforce
  sudo kill -USR2 "$(pgrep zqfw)"   # dump the live session table
  ```

### Tuning

| flag | default | meaning |
|------|---------|---------|
| `--threshold` | 0.8 | risk score needing to quarantine (0–1) |
| `--quarantine` | 5m | how long a blocked IP/flow stays blocked (e.g. `30s`, `5m`) |
| `--reap-interval` | 5s | supervisor re-evaluation period |
| `--monitor` | off | never drop — observe/audit only |
| `--block-ip` | off | whole-IP quarantines on systemic behaviour (port scan) |
| `--metrics-addr` | 127.0.0.1:9790 | Prometheus text endpoint |
| `--audit` | `-` | JSONL audit path (`-` for stdout) |

## Metrics & observability

* **Audit** (`--audit audit.jsonl`): every decision with risk, signals, weights,
  confidence, latency, and the exact kernel map written.
* **Prometheus**: `curl localhost:9790/metrics` →
  `zqfw_packets_passed_total`, `zqfw_packets_dropped_total`,
  `zqfw_block_hits_total`, `zqfw_quarantined_ips`, ...
* **Signals**: SIGUSR1 toggle, SIGUSR2 session dump.

## Architecture

```
 userspace                                            kernel
 ┌──────────────────────────────────┐   Rake   ┌─────────────────────────┐
 │ zqfw (Rust daemon)                 │       │ firewall.bpf.c         │
 │ supervisor ─(2s)─────────────────┐─────────▶│ ┌ XDP (ingress)        │
 │  · ring-buffer flow merge         │         │ └ TC (in/egress)       │
 │  · 60s triage context            │──map────▶│   ·parse ETH/IP/TCP/UDP│
 │  · risk = Σ(w·c)/Σ(w)            │─────────▶│   ·flow metrics        │
 │  · write blocklist/blocklist_ip  │         │   · blocklist lookups   │
 │  · TTL expiry → auto-revert      │         │   · drop / pass        │
 │ audit · metrics · SIGHUP         │         │ maps: flows, blocklist, │
 └──────────────────────────────────┘         │ blocklist_ip, events,   │
                                                │ ctl, counters           │
                                                └─────────────────────────┘
```

Full design notes: `docs/README.md` and `docs/FINAL_REPORT.md`.

## Testing

```bash
cargo test          # 9 unit tests: byte-order, triage, BPF object parse
```

Live-system verification and the 7 bugs found are in [`RESULTS.md`](RESULTS.md#4-bugs-found-and-fixed-during-real-mode-testing).

## FAQ

***Does it really enforce, or is it just monitoring?*** — Yes, it really
  enforces: once monitor mode is toggled off (SIGUSR1), the probes drop packets
  in the kernel. Undetected flows pass; quarantined flows/IPs are dropped with
  a counter increment read back from the kernel map.
* **Will it block my own traffic?** — On a live host, "first contact" to a new
  destination can look suspicious (8 weighted signals, threshold 0.8). Run
  `--monitor` first and review the audit before you enforce.
* **Why root?** — loading eBPF requires `CAP_BPF/CAP_SYS_ADMIN/CAP_NET_ADMIN`.
  A demo does not — use `--mock`.

## Disclaimer

This tool blocks network traffic and can break connectivity if misconfigured
or confused by traffic it should ignore. Run in monitor mode first; treat the
audit log as the source of truth before enforcing.