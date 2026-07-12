use std::{
    collections::BTreeMap,
    fmt::Write as _,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

use crate::error::Result;

#[derive(Debug, Default)]
pub struct RouteMetrics {
    pub active_tunnels: AtomicU64,
    pub active_streams: AtomicU64,
    pub accepted_streams: AtomicU64,
    pub refused_streams: AtomicU64,
    pub bytes_member_to_node: AtomicU64,
    pub bytes_node_to_member: AtomicU64,
    pub tunnel_replacements: AtomicU64,
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    routes: Arc<Mutex<BTreeMap<String, Arc<RouteMetrics>>>>,
    auth_failures: Arc<AtomicU64>,
    protocol_failures: Arc<AtomicU64>,
    config_reload_failures: Arc<AtomicU64>,
}

impl Metrics {
    #[must_use]
    pub fn route(&self, route_id: &str) -> Arc<RouteMetrics> {
        let mut routes = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        routes
            .entry(route_id.to_owned())
            .or_insert_with(|| Arc::new(RouteMetrics::default()))
            .clone()
    }

    pub fn remove_route(&self, route_id: &str) {
        self.routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(route_id);
    }

    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_protocol_failure(&self) {
        self.protocol_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reload_failure(&self) {
        self.config_reload_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut output = String::with_capacity(4_096);
        output.push_str("# TYPE relay_auth_failures_total counter\n");
        writeln!(
            output,
            "relay_auth_failures_total {}",
            self.auth_failures.load(Ordering::Relaxed)
        )
        .expect("writing to String cannot fail");
        output.push_str("# TYPE relay_protocol_failures_total counter\n");
        writeln!(
            output,
            "relay_protocol_failures_total {}",
            self.protocol_failures.load(Ordering::Relaxed)
        )
        .expect("writing to String cannot fail");
        output.push_str("# TYPE relay_config_reload_failures_total counter\n");
        writeln!(
            output,
            "relay_config_reload_failures_total {}",
            self.config_reload_failures.load(Ordering::Relaxed)
        )
        .expect("writing to String cannot fail");

        let routes = self
            .routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (route_id, metrics) in routes.iter() {
            let label = prometheus_label(route_id);
            for (name, value) in [
                (
                    "relay_route_active_tunnels",
                    metrics.active_tunnels.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_active_streams",
                    metrics.active_streams.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_accepted_streams_total",
                    metrics.accepted_streams.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_refused_streams_total",
                    metrics.refused_streams.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_bytes_member_to_node_total",
                    metrics.bytes_member_to_node.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_bytes_node_to_member_total",
                    metrics.bytes_node_to_member.load(Ordering::Relaxed),
                ),
                (
                    "relay_route_tunnel_replacements_total",
                    metrics.tunnel_replacements.load(Ordering::Relaxed),
                ),
            ] {
                writeln!(output, "{name}{{route_id=\"{label}\"}} {value}")
                    .expect("writing to String cannot fail");
            }
        }
        output
    }
}

pub async fn serve_metrics(
    listener: TcpListener,
    metrics: Metrics,
    shutdown: CancellationToken,
) -> Result<()> {
    let connection_slots = Arc::new(Semaphore::new(8));
    loop {
        let permit = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            permit = connection_slots.clone().acquire_owned() => permit.expect("metrics semaphore remains open"),
        };
        let (mut socket, _peer) = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut request = [0_u8; 2_048];
            let Ok(Ok(read)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut request))
                    .await
            else {
                return;
            };
            let first_line = request[..read]
                .split(|byte| *byte == b'\n')
                .next()
                .and_then(|line| std::str::from_utf8(line).ok())
                .unwrap_or_default()
                .trim_end_matches('\r');
            let (status, content_type, body) = match first_line {
                "GET /metrics HTTP/1.1" | "GET /metrics HTTP/1.0" => (
                    "200 OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    metrics.render(),
                ),
                "GET /healthz HTTP/1.1" | "GET /healthz HTTP/1.0" => {
                    ("200 OK", "text/plain; charset=utf-8", "ok\n".to_owned())
                }
                _ => (
                    "404 Not Found",
                    "text/plain; charset=utf-8",
                    "not found\n".to_owned(),
                ),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}

pub async fn bind_metrics(address: SocketAddr) -> Result<TcpListener> {
    Ok(TcpListener::bind(address).await?)
}

fn prometheus_label(value: &str) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_contain_only_opaque_route_metadata() {
        let metrics = Metrics::default();
        let route = metrics.route("route_0123456789abcdef");
        route.accepted_streams.store(2, Ordering::Relaxed);
        route.bytes_member_to_node.store(512, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("route_id=\"route_0123456789abcdef\""));
        assert!(rendered.contains("accepted_streams_total"));
        assert!(rendered.contains(" 512"));
        assert!(!rendered.contains("client_ip"));
        assert!(!rendered.contains("payload"));
    }
}
