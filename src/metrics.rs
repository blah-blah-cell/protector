//! Tiny Prometheus text-format exporter over a local TCP socket.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::pipeline::MetricsState;

pub async fn serve(addr: SocketAddr, state: Arc<Mutex<MetricsState>>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("metrics exporter listening on {addr}");
    loop {
        let (mut socket, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let st = state.lock().await;
            let body = render(&*st);
            drop(st);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        });
    }
}

fn render(m: &MetricsState) -> String {
    let enforce = if m.enforce { 1 } else { 0 };
    format!(
        "# HELP zqfw_packets_total Packets evaluated by the probes.\n\
         # TYPE zqfw_packets_total counter\n\
         zqfw_packets_passed_total {pass}\n\
         zqfw_packets_dropped_total {drop}\n\
         # HELP zqfw_block_hits_total Quarantined flows that hit the blocklist.\n\
         # TYPE zqfw_block_hits_total counter\n\
         zqfw_block_hits_total {block_hits}\n\
         zqfw_new_flows_total {new_flows}\n\
         zqfw_malformed_total {malformed}\n\
         zqfw_events_lost_total {events_lost}\n\
         # HELP zqfw_sessions Current in-memory sessions.\n\
         # TYPE zqfw_sessions gauge\n\
         zqfw_sessions {sessions}\n\
         zqfw_quarantined_flows {quarantined_flows}\n\
         zqfw_quarantined_ips {quarantined_ips}\n\
         zqfw_decisions_total {decisions}\n\
         # HELP zqfw_enforce Enforcement mode (1=drop, 0=monitor).\n\
         # TYPE zqfw_enforce gauge\n\
         zqfw_enforce {enforce}\n",
        pass = m.pass,
        drop = m.drop,
        block_hits = m.block_hits,
        new_flows = m.new_flows,
        malformed = m.malformed,
        events_lost = m.events_lost,
        sessions = m.sessions,
        quarantined_flows = m.quarantined_flows,
        quarantined_ips = m.quarantined_ips,
        decisions = m.decisions,
        enforce = enforce,
    )
}
