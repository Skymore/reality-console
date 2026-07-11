use anyhow::{bail, Context as _, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout, Instant};

const DEFAULT_MAX_CONNECTIONS: usize = 16;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_CANARY_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const MAX_CONNECTIONS: usize = 4_096;
const MAX_GATE_DELAY: Duration = Duration::from_secs(60);
const LISTEN_BACKLOG: u32 = 128;

#[derive(Debug, Clone, Copy)]
pub(crate) struct AdmissionOptions {
    pub max_connections: usize,
    pub connect_timeout: Duration,
    pub canary_timeout: Duration,
    pub probe_interval: Duration,
    pub accept_error_backoff: Duration,
}

impl Default for AdmissionOptions {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            canary_timeout: DEFAULT_CANARY_TIMEOUT,
            probe_interval: DEFAULT_PROBE_INTERVAL,
            accept_error_backoff: DEFAULT_ACCEPT_ERROR_BACKOFF,
        }
    }
}

impl AdmissionOptions {
    pub(crate) fn validate(self) -> Result<Self> {
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS {
            bail!("admission connection limit must be between 1 and {MAX_CONNECTIONS}");
        }
        for (name, value) in [
            ("connect timeout", self.connect_timeout),
            ("canary timeout", self.canary_timeout),
            ("probe interval", self.probe_interval),
            ("accept error backoff", self.accept_error_backoff),
        ] {
            if value.is_zero() || value > MAX_GATE_DELAY {
                bail!("admission {name} must be non-zero and at most 60 seconds");
            }
        }
        if self.probe_interval > self.canary_timeout {
            bail!("admission probe interval cannot exceed its canary timeout");
        }
        Ok(self)
    }
}

/// Owns the byte-transparent public TCP listener for one applied revision.
#[derive(Debug)]
pub(crate) struct AdmissionGate {
    public_port: u16,
    backend: SocketAddr,
    successful_loopback_connections: Arc<AtomicU64>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
    options: AdmissionOptions,
}

impl AdmissionGate {
    pub(crate) fn start(
        public_port: u16,
        backend_port: u16,
        options: AdmissionOptions,
    ) -> Result<Self> {
        if public_port == 0 || backend_port == 0 || public_port == backend_port {
            bail!("admission public and backend ports must be distinct and non-zero");
        }
        let options = options.validate()?;
        let socket =
            TcpSocket::new_v4().context("public IPv4 admission socket could not be created")?;
        #[cfg(unix)]
        socket
            .set_reuseaddr(true)
            .context("public IPv4 admission socket could not enable address reuse")?;
        socket
            .bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                public_port,
            ))
            .with_context(|| format!("public admission port {public_port} could not be bound"))?;
        let listener = socket
            .listen(LISTEN_BACKLOG)
            .context("public admission socket could not begin listening")?;
        let backend = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port);
        let successful_loopback_connections = Arc::new(AtomicU64::new(0));
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(run_gate(
            listener,
            backend,
            options,
            Arc::clone(&successful_loopback_connections),
            shutdown_receiver,
        ));
        Ok(Self {
            public_port,
            backend,
            successful_loopback_connections,
            shutdown: Some(shutdown),
            task: Some(task),
            options,
        })
    }

    pub(crate) fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    /// Checks the active loopback backend without consuming a provider stream
    /// slot. The activation canary separately proves the public listener path.
    pub(crate) async fn prove_backend_ready(&self) -> Result<()> {
        if !self.is_running() {
            bail!("public admission gate is not running");
        }
        timeout(
            self.options.connect_timeout,
            TcpStream::connect(self.backend),
        )
        .await
        .context("admission backend health check timed out")?
        .context("admission backend health check failed")?;
        Ok(())
    }

    /// Proves that a connection accepted through the public listener reached
    /// the candidate's loopback listener without sending protocol bytes.
    pub(crate) async fn prove_ready(&self) -> Result<()> {
        if !self.is_running() {
            bail!("public admission gate exited before its local canary");
        }
        let previous = self.successful_loopback_connections.load(Ordering::Acquire);
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.public_port);
        let client = timeout(self.options.connect_timeout, TcpStream::connect(address))
            .await
            .context("public admission canary connection timed out")?
            .context("public admission canary could not connect")?;
        let deadline = Instant::now() + self.options.canary_timeout;
        loop {
            if self.successful_loopback_connections.load(Ordering::Acquire) > previous {
                drop(client);
                return Ok(());
            }
            if !self.is_running() {
                bail!("public admission gate exited during its local canary");
            }
            if Instant::now() >= deadline {
                bail!("public admission gate could not reach the Xray loopback listener");
            }
            sleep(self.options.probe_interval).await;
        }
    }

    /// Stops accepting streams, aborts active copies, and reaps the owner task.
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let joined = match self.task.as_mut() {
            Some(task) => task.await,
            None => return Ok(()),
        };
        self.task = None;
        joined.context("public admission owner task could not be reaped")?
    }
}

impl Drop for AdmissionGate {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_gate(
    listener: TcpListener,
    backend: SocketAddr,
    options: AdmissionOptions,
    successful_loopback_connections: Arc<AtomicU64>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(options.max_connections));
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                log_connection_result(result);
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((client, peer)) => {
                        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                            tracing::debug!(peer = %peer, "admission connection limit reached");
                            continue;
                        };
                        let successes = Arc::clone(&successful_loopback_connections);
                        connections.spawn(async move {
                            let _permit = permit;
                            client.set_nodelay(true).context("admission client socket setup failed")?;
                            let mut backend_stream = timeout(
                                options.connect_timeout,
                                TcpStream::connect(backend),
                            )
                            .await
                            .context("admission backend connection timed out")?
                            .context("admission backend connection failed")?;
                            backend_stream
                                .set_nodelay(true)
                                .context("admission backend socket setup failed")?;
                            if peer.ip().is_loopback() {
                                successes.fetch_add(1, Ordering::Release);
                            }
                            let mut client = client;
                            copy_bidirectional(&mut client, &mut backend_stream)
                                .await
                                .context("admission byte stream failed")?;
                            Ok::<(), anyhow::Error>(())
                        });
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "public admission accept failed; retrying");
                        tokio::select! {
                            _ = &mut shutdown => break,
                            () = sleep(options.accept_error_backoff) => {}
                        }
                    }
                }
            }
        }
    }

    connections.abort_all();
    while let Some(result) = connections.join_next().await {
        if result
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled)
        {
            continue;
        }
        log_connection_result(result);
    }
    Ok(())
}

fn log_connection_result(result: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(error = %error, "admission stream closed with an error"),
        Err(error) if error.is_cancelled() => {}
        Err(error) => tracing::warn!(error = %error, "admission stream task failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionGate, AdmissionOptions};
    use crate::test_support::{
        bind_unique_loopback, bind_unique_wildcard, lock_network_tests, unique_unused_port,
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    fn fast_options() -> AdmissionOptions {
        AdmissionOptions {
            max_connections: 2,
            connect_timeout: Duration::from_millis(100),
            canary_timeout: Duration::from_millis(200),
            probe_interval: Duration::from_millis(5),
            accept_error_backoff: Duration::from_millis(5),
        }
    }

    #[tokio::test]
    async fn gate_proves_and_forwards_the_byte_stream() {
        let _network_test_lock = lock_network_tests().await;
        let backend = bind_unique_loopback().await;
        let backend_port = backend.local_addr().unwrap().port();
        let backend_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = backend.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4];
                    if stream.read_exact(&mut buffer).await.is_ok() {
                        stream.write_all(&buffer).await.unwrap();
                    }
                });
            }
        });
        let public_port = unique_unused_port().await;
        let mut gate = AdmissionGate::start(public_port, backend_port, fast_options()).unwrap();

        gate.prove_ready().await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        gate.shutdown().await.unwrap();
        assert!(TcpStream::connect(("127.0.0.1", public_port))
            .await
            .is_err());
        backend_task.abort();
        backend_task.await.unwrap_err();
    }

    #[tokio::test]
    async fn gate_canary_fails_when_the_backend_is_unavailable() {
        let _network_test_lock = lock_network_tests().await;
        let backend_port = unique_unused_port().await;
        let public_port = unique_unused_port().await;
        assert_ne!(backend_port, public_port);
        let mut gate = AdmissionGate::start(public_port, backend_port, fast_options()).unwrap();

        let error = gate.prove_ready().await.unwrap_err();

        assert!(error.to_string().contains("could not reach"));
        gate.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn occupied_public_port_fails_before_spawning_an_owner_task() {
        let _network_test_lock = lock_network_tests().await;
        let occupied = bind_unique_wildcard().await;
        let public_port = occupied.local_addr().unwrap().port();
        let backend_port = unique_unused_port().await;

        let error = AdmissionGate::start(public_port, backend_port, fast_options()).unwrap_err();

        assert!(error.to_string().contains("could not be bound"));
    }

    #[tokio::test]
    async fn dropping_gate_releases_its_listener_and_connection_tasks() {
        let _network_test_lock = lock_network_tests().await;
        let backend = bind_unique_loopback().await;
        let backend_port = backend.local_addr().unwrap().port();
        let public_port = unique_unused_port().await;
        let gate = AdmissionGate::start(public_port, backend_port, fast_options()).unwrap();
        let client = TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        let (_backend_stream, _) = backend.accept().await.unwrap();

        drop(gate);
        drop(client);

        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if let Ok(listener) = TcpListener::bind(("0.0.0.0", public_port)).await {
                    drop(listener);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("dropped admission gate kept its public port bound");
    }

    #[tokio::test]
    async fn connection_limit_refuses_excess_streams_and_releases_permits() {
        let _network_test_lock = lock_network_tests().await;
        let backend = bind_unique_loopback().await;
        let backend_port = backend.local_addr().unwrap().port();
        let public_port = unique_unused_port().await;
        let mut options = fast_options();
        options.max_connections = 1;
        let mut gate = AdmissionGate::start(public_port, backend_port, options).unwrap();
        let first_client = TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        let (first_backend, _) = backend.accept().await.unwrap();

        let mut refused = TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(200), refused.read(&mut byte))
            .await
            .expect("excess admission stream was not refused")
            .unwrap();
        assert_eq!(read, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), backend.accept())
                .await
                .is_err()
        );

        drop(first_client);
        drop(first_backend);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let third_client = TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        let third_backend = tokio::time::timeout(Duration::from_millis(200), backend.accept())
            .await
            .expect("released admission permit was not reusable")
            .unwrap();
        drop(third_client);
        drop(third_backend);
        gate.shutdown().await.unwrap();
    }

    #[test]
    fn options_reject_unbounded_or_zero_values() {
        assert!(AdmissionOptions::default().validate().is_ok());
        assert!(AdmissionOptions {
            max_connections: 0,
            ..AdmissionOptions::default()
        }
        .validate()
        .is_err());
        assert!(AdmissionOptions {
            canary_timeout: Duration::ZERO,
            ..AdmissionOptions::default()
        }
        .validate()
        .is_err());
    }
}
