//! Runtime configuration: CLI flags + environment overrides.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::bail;
use clap::Parser;
use ipnet::IpNet;

/// Name used to ask for automatic interface selection.
const AUTO_IFACE: &str = "auto";

/// Env var that can force a specific interface.
const IFACE_ENV: &str = "ZQFW_IFACE";

#[derive(Debug, Clone, Parser)]
#[command(
    name = "zqfw",
    about = "eBPF-driven zero-trust quarantine controller",
    version
)]
pub struct Cli {
    /// Network interface to attach XDP/TC probes to (real mode only).
    /// "auto" selects the default-route interface.
    #[arg(long, default_value = AUTO_IFACE)]
    pub iface: String,

    /// Run without kernel access using a synthetic traffic generator.
    #[arg(long)]
    pub mock: bool,

    /// XDP attach mode: driver, skb, or default.
    #[arg(long, default_value = "default", value_parser = ["default", "skb", "driver"])]
    pub xdp_mode: String,

    /// Start in monitor mode (observe, never drop). Use SIGUSR1 to toggle.
    #[arg(long)]
    pub monitor: bool,

    /// Risk threshold in [0,1]; decisions above this quarantine the flow.
    #[arg(long, default_value_t = 0.8)]
    pub threshold: f64,

    /// Quarantine duration.
    #[arg(long, value_parser = humantime, default_value = "5m")]
    pub quarantine: Duration,

    /// Re-evaluation / reaper interval.
    #[arg(long, value_parser = humantime, default_value = "5s")]
    pub reap_interval: Duration,

    /// Idle flow expiry.
    #[arg(long, value_parser = humantime, default_value = "60s")]
    pub flow_ttl: Duration,

    /// Also quarantine whole source IPs on systemic behaviour (port scan etc.).
    #[arg(long)]
    pub block_ip: bool,

    /// Emit block-hit events into the ring buffer (ratelimited by the kernel).
    #[arg(long)]
    pub hit_events: bool,

    /// Audit log path; "-" for stdout.
    #[arg(long, default_value = "-")]
    pub audit: String,

    /// Prometheus metrics bind address.
    #[arg(long, default_value = "127.0.0.1:9790")]
    pub metrics_addr: SocketAddr,

    /// Directory where pinned BPF maps live (for troubleshooting).
    #[arg(long)]
    pub pin_dir: Option<PathBuf>,

    /// Comma-separated list of CIDR prefixes (e.g. 10.0.0.0/8,192.168.1.0/24)
    /// that are exempt from quarantine. Exact IPs also accepted (/32, /128).
    #[arg(long, value_delimiter = ',')]
    pub allowlist: Vec<String>,
}

fn humantime(s: &str) -> Result<Duration, String> {
    s.parse::<humantime::Duration>()
        .map(Into::into)
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub cli: Cli,
    /// Quarantine duration in nanoseconds (written into the ctl map).
    pub block_ttl_ns: u64,
    /// Whether to enable whole-IP quarantine.
    pub block_ip: bool,
    /// Parsed allowlist entries (CIDR or exact IPs).
    pub allowlist: Vec<IpNet>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let mut cli = Cli::parse();

        // Allow an explicit environment override (useful for systemd).
        if let Ok(v) = std::env::var(IFACE_ENV) {
            if !v.is_empty() {
                cli.iface = v;
            }
        }

        // Resolve the "auto" placeholder to the default-route interface so the
        // program works out of the box on any host/NIC naming (eth0, enp0s3,
        // ens33, wlan0, ...). Mock mode never attaches so it is left untouched.
        if cli.iface == AUTO_IFACE && !cli.mock {
            match resolve_default_interface() {
                Some(name) => {
                    cli.iface = name;
                    tracing::info!("auto-selected interface: {}", cli.iface);
                }
                None => bail!(
                    "no default-route interface found; pass --iface <name> or set {IFACE_ENV}"
                ),
            }
        }

        let block_ttl_ns = cli
            .quarantine
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let block_ip = cli.block_ip;

        // Parse allowlist CIDR strings
        let mut allowlist = Vec::new();
        for cidr in &cli.allowlist {
            match cidr.parse::<IpNet>() {
                Ok(net) => allowlist.push(net),
                Err(e) => bail!("invalid allowlist CIDR '{cidr}': {e}"),
            }
        }

        Ok(Config {
            cli,
            block_ttl_ns,
            block_ip,
            allowlist,
        })
    }
}

/// Pick the interface carrying the IPv4 default route by parsing
/// /proc/net/route (works on Linux; no extra deps, no netlink).
fn resolve_default_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let dest = fields.next().unwrap_or_default();
        // 00000000 (host-order 0x00000000) == the default route.
        if dest == "00000000" {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_iface_is_a_supported_literal() {
        assert_eq!(AUTO_IFACE, "auto");
    }
}
