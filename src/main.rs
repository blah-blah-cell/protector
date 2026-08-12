mod audit;
mod bpf;
mod config;
mod flow;
mod metrics;
mod mock;
mod pipeline;
mod protocol;
mod traffic;
mod triage;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bpf::DataPlane;
use config::Config;
use pipeline::{MetricsState, Supervisor};
use tokio::sync::{mpsc, watch, Mutex};

/// Best-effort `sd_notify(3)` replacement: sends a datagram to the socket
/// named by `$NOTIFY_SOCKET` (set by systemd when `Type=notify`). No-op if
/// the variable is unset or the socket can't be reached, so it is always
/// safe to call outside of systemd.
#[cfg(target_os = "linux")]
fn sd_notify(state: &str) {
    use std::os::unix::net::UnixDatagram;
    if let Ok(addr) = std::env::var("NOTIFY_SOCKET") {
        if let Ok(sock) = UnixDatagram::unbound() {
            let _ = sock.send_to(state.as_bytes(), addr);
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("zqfw=info,info")),
        )
        .init();
}

/// Forwards ring-buffer events from the kernel data plane into the event
/// channel. Uses `AsyncFd` for sub-millisecond wakeups, falling back to a 1ms
/// poll loop if the fd can't be registered with tokio.
async fn spawn_kernel_event_poller(
    plane: Arc<Mutex<Box<dyn DataPlane + Send>>>,
    tx: mpsc::Sender<protocol::KernelEvent>,
) {
    let Some(fd) = plane.lock().await.event_fd() else {
        return;
    };

    match tokio::io::unix::AsyncFd::new(fd) {
        Ok(async_fd) => {
            tokio::spawn(async move {
                loop {
                    let mut guard = match async_fd.readable().await {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    let mut evs = Vec::with_capacity(64);
                    let n = plane.lock().await.poll_events(&mut evs).unwrap_or(0);
                    for ev in evs {
                        let _ = tx.send(ev).await;
                    }
                    guard.clear_ready();
                    if n == 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            });
        }
        Err(_) => {
            tracing::warn!("AsyncFd registration failed; using 1ms poll loop");
            tokio::spawn(async move {
                loop {
                    let mut evs = Vec::with_capacity(64);
                    let _ = plane.lock().await.poll_events(&mut evs);
                    for ev in evs {
                        let _ = tx.send(ev).await;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;

    let audit = Arc::new(Mutex::new(audit::AuditLogger::new(&cfg.cli.audit)?));
    let metrics_state = Arc::new(Mutex::new(MetricsState::default()));
    let (tx, rx) = mpsc::channel::<protocol::KernelEvent>(16_384);
    let (stop_tx, stop_rx) = watch::channel(false);

    // Build the data plane: real BPF (needs root) or the rootless simulator.
    let plane: Arc<Mutex<Box<dyn DataPlane + Send>>>;

    if cfg.cli.mock {
        let mock = mock::MockDataPlane::new();
        plane = Arc::new(Mutex::new(Box::new(mock)));
        let sim_plane = plane.clone();
        let sim_tx = tx.clone();
        let sim_stop = stop_rx.clone();
        tokio::spawn(async move {
            traffic::sim::run_simulator(sim_plane, sim_tx, sim_stop).await;
        });
        tracing::warn!(
            "mock mode: no BPF probes attached; driving synthetic traffic on iface={}",
            cfg.cli.iface
        );
    } else {
        let bpf = bpf::BpfManager::load(&cfg)?;
        plane = Arc::new(Mutex::new(Box::new(bpf)));
        spawn_kernel_event_poller(plane.clone(), tx.clone()).await;
        tracing::info!(
            "XDP/TC probes attached to {} in {} mode",
            cfg.cli.iface,
            if cfg.cli.monitor { "monitor" } else { "enforce" }
        );
    }

    // Metrics exporter (Prometheus text on a local TCP socket).
    let metrics_addr = cfg.cli.metrics_addr;
    {
        let state = metrics_state.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(metrics_addr, state).await {
                tracing::error!("metrics exporter: {e}");
            }
        });
    }

    // Supervision loop.
    let mut sup = Supervisor {
        plane,
        table: flow::SessionTable::default(),
        ctrl: triage::TriageController::new(
            cfg.cli.threshold,
            cfg.block_ttl_ns / 1_000_000,
            cfg.block_ip,
        ),
        cfg,
        metrics: metrics_state,
        audit,
        enforce: false,
        llm: triage::llm::LlmBackend::from_env(),
        quarantined_ips_expiry: Vec::new(),
        decisions: Default::default(),
    };

    // Graceful shutdown on Ctrl-C.
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown requested (Ctrl-C)");
        let _ = stop_tx.send(true);
    };
    tokio::pin!(shutdown);

    // Fail-closed on SIGTERM: stop the supervisor loop but leave the eBPF
    // probes attached so any active quarantines keep being enforced by the
    // kernel until the process is fully reaped or the host reboots.
    let term = async {
        let mut term_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        term_signal.recv().await;
        tracing::warn!("SIGTERM received - entering fail-closed mode");
        let _ = stop_tx.send(true);
    };
    tokio::pin!(term);

    // Systemd watchdog ping: send WATCHDOG=1 periodically if NOTIFY_SOCKET is
    // set (i.e. the unit uses `Type=notify` + `WatchdogSec=`).
    let watchdog = async {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if std::env::var("NOTIFY_SOCKET").is_ok() {
                sd_notify("WATCHDOG=1");
            }
        }
    };
    tokio::pin!(watchdog);

    tokio::select! {
        _ = &mut shutdown => {}
        _ = &mut term => {}
        _ = &mut watchdog => {}
        r = sup.run(rx) => r?,
    }

    tracing::info!("supervisor exited; probes remain attached (fail-closed)");
    Ok(())
}
