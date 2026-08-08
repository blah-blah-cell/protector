# Test Results — zqfw eBPF Agentic Firewall

Date: 2026-08-08 · Kernel: 6.19.14+kali-amd64 · Interfaces: eth0 (192.168.31.250/24), lo

## 1. Unit tests

| Suite | Result |
|-------|--------|
| protocol round-trips (IPv4/IPv6, FlowKey layout) | 4/4 pass |
| triage decisions (benign→Allow, SYN flood→Quarantine, scan→QuarantineIp) | 3/3 pass |
| BPF object parses (programs + maps discovered) | 1/1 pass |
| **Total** | **8/8 pass** |

## 2. Mock end-to-end (no root, synthetic traffic)

Run: `zqfw --mock --block-ip --quarantine 20s --reap-interval 2s --audit audit.jsonl`

All five attack scenarios were detected and quarantined. Decision latency per
enforcement was 0.001–0.013 ms (mock data plane):

| Attack | Decision | Signals | Risk |
|--------|----------|---------|------|
| Port scan (198.51.100.10 → 10.0.0.5) | `quarantine_ip` | port_scan, syn_flood | 1.0 |
| SYN flood (198.51.100.11 → 10.0.0.5:443) | `quarantine` | syn_flood | 1.0 |
| DNS tunnel (203.0.113.7 → 10.0.0.53:53) | `quarantine` | dns_tunnel | 1.0 |
| Data exfiltration (10.0.0.12 → 203.0.113.99:5555) | `quarantine` | data_exfil, unidirectional_udp | 0.89–0.91 |
| Lateral movement (10.0.0.5 → 10.0.0.20:22) | `quarantine` | lateral_movement, syn_flood | 1.0 |

Also verified in mock mode:
- Quarantine TTL expiry → `isolation_released` / `ip_isolation_released`
  (self-heal cycle), re-quarantine while the attack persists.
- Dedup: a port-scan source is IP-quarantined once per window, not per session.
- SIGUSR1 toggles enforce↔monitor (`mode_toggle` audit event); SIGUSR2 dumps
  the session table (`session_dump`).

## 3. Real mode (root, live eth0)

Run: `sudo zqfw --iface eth0 --block-ip --monitor --quarantine 30s --flow-ttl 10s --reap-interval 2s`

Attack generator: `sudo hping3 -S -p 1-100 -c 100 -i u100 192.168.31.1`
(SYN scan of the LAN gateway, 100 distinct ports).

### 3.1 Attach

`XDP/TC probes attached to eth0` — both programs verified by the kernel
verifier and attached (XDP default mode + TC ingress/egress).

### 3.2 Detection & decision (monitor mode)

~2 s after the scan (one reap interval), real packets were classified and two
decisions written to the real kernel maps:

```
quarantine_ip 192.168.31.250  risk 1.0  lat_ms 0.0209  [syn_flood]
quarantine_ip 192.168.31.1    risk 1.0  lat_ms 0.0035  [port_scan]
```

- 192.168.31.250 (the scanner's own IP) — IP quarantine
- 192.168.31.1 (the gateway; its RST replies looked like a scan) — IP quarantine

### 3.3 In-kernel enforcement (enforce mode)

After `SIGUSR1` toggle to enforce, counters read from the kernel map:

```
zqfw_packets_passed_total 263    zqfw_packets_dropped_total 18   block_hits 18
zqfw_packets_dropped_total 23    block_hits 23   (after 4 pings -> all dropped)
zqfw_packets_dropped_total 34    block_hits 34   (ambient traffic, end of test)
```

`ping 192.168.31.1` during the quarantine window: **100% packet loss** — the
packets were dropped in the kernel by the blocklist_ip map. `dropped_total` and
`block_hits_total` incremented 1:1 with blocked packets, confirming the
counters reflect real enforcement.

### 3.4 TTL lifecycle (self-heal cycle)

From the audit timeline (ts relative to supervisor start):

```
t= 6s  isolation_enforced    quarantine_ip 192.168.31.250 / 192.168.31.1
t=36s  ip_isolation_released ttl_expired   (30s quarantine window elapsed)
t=38s  isolation_enforced    re-quarantine — evidence still present
t=68s  ip_isolation_released ttl_expired
t=70s  isolation_enforced    re-quarantine — evidence still present
```

Quarantines expire at their TTL and are only re-established when the triage
sees fresh evidence (in this environment the VM's own outbound traffic
presents SYN-flood-like patterns, so the host's IP is re-quarantined while
those sessions persist). With `--flow-ttl`, session evidence ages out; the
release/re-enforce cycle above is the observed behavior.

## 4. Bugs found and fixed during real-mode testing

| # | Bug | Fix |
|---|-----|-----|
| 1 | `src_ip()`/`dst_ip()` used `.to_be()`, producing reversed IPs (e.g. `7.113.0.203` for `203.0.113.7`) | Removed `to_be()`; `Ipv4Addr::from(u32)` interprets the value as big-endian, matching `from_be_bytes` |
| 2 | Kernel wrote raw network-order bytes into `saddr[]/daddr[]` (LE-host confusion, reversed IPs in real mode: `250.31.168.192`) | `bpf_ntohl()` on IPv4 (and per-u32 IPv6) before storing; verified real IPs (`192.168.31.250`) and IPv6 |
| 3 | `counters` is a 1-entry array but the C code looked up indices 1/3/4 (drop/new_flows/malformed) — out-of-range → NULL → those counters never incremented (only `pass` worked) | All counter lookups use index 0 |
| 4 | `block_hits` never incremented anywhere in the C source | Increment alongside `drop` on both blocklist-hit paths |
| 5 | Mock plane never tracked TCP flags (hardcoded `0x12`), so `syn_flood`/`rst_flood` could never fire in mock mode | Threaded per-flow `flags` through `FlowSpec` → `ingest_packet` → `process_packet` |
| 6 | `first_seen_ns`/`last_seen_ns` were `u32` (32-bit ns wraps every 4.3 s; boottime values truncated) | Promoted to `u64` in the wire struct, mock, and C mirror |
| 7 | Mock timestamps were flow-relative while triage uses boottime — rate signals saw huge bogus durations | Simulator now emits `boottime_ns()`-based absolute timestamps |

## 5. Caveats / design notes

- **Zero-trust false positives on a live host**: any new contact from a private
  host to a public endpoint fires `first_contact` (risk 0.8 alone = threshold);
  a host's own first-contact traffic and SYN-retransmit patterns can trigger
  quarantines of the host's own IP in enforce mode. Deploy monitor-first;
  consider allow-listing for known-good sources.
- XDP default mode worked on this virtio NIC; use `--xdp-mode skb` where driver
  mode is unsupported.
- Ring-buffer events for every new flow saturate under heavy scans — the
  kernel ratelimits via `events_lost`; decisions are unaffected (they run off
  the flow map snapshot).
