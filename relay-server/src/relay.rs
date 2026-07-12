use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, OwnedSemaphorePermit, RwLock, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::{
    config::{RelayConfig, RouteConfig, ServerConfig},
    error::{ErrorCode, RelayError, Result},
    flow::{Credit, RateLimiter},
    frame::{Frame, FrameKind},
    metrics::{bind_metrics, serve_metrics, Metrics, RouteMetrics},
    tls::{build_acceptor, certificate_sha256},
};

const REGISTER_TOKEN_MAX_BYTES: usize = 256;
/// Starts and owns the relay service.
pub struct RelayServer;

/// Running relay handle. Dropping it requests shutdown; call [`RelayHandle::shutdown`] to wait.
#[derive(Clone)]
pub struct RelayHandle {
    state: Arc<ServerState>,
}

struct ServerState {
    server_config: ServerConfig,
    configured_routes: RwLock<HashMap<String, RouteConfig>>,
    active_routes: RwLock<HashMap<String, Arc<RouteRuntime>>>,
    tls_acceptor: TlsAcceptor,
    metrics: Metrics,
    shutdown: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    node_address: SocketAddr,
    metrics_address: SocketAddr,
}

struct RouteRuntime {
    config: RouteConfig,
    public_address: SocketAddr,
    server_config: ServerConfig,
    tunnel: Mutex<Option<Arc<TunnelSession>>>,
    stream_slots: Arc<Semaphore>,
    next_stream_id: AtomicU64,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<RouteMetrics>,
    cancel: CancellationToken,
}

struct TunnelSession {
    id: u64,
    command_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u64, Arc<StreamDispatch>>>>,
    last_pong: Mutex<Instant>,
    cancel: CancellationToken,
}

struct StreamDispatch {
    open_result: Mutex<Option<oneshot::Sender<std::result::Result<u32, ErrorCode>>>>,
    inbound_tx: mpsc::Sender<Inbound>,
    receive_remaining: AtomicU64,
    send_credit: Credit,
    cancel: CancellationToken,
}

enum Inbound {
    Data(Vec<u8>),
    Fin,
    Close,
}

struct Activity {
    started: Instant,
    last_payload: Mutex<Instant>,
    bytes: AtomicU64,
}

impl RelayServer {
    /// Starts all configured route, node-tunnel, and loopback metrics listeners.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration or TLS material is invalid or a required listener
    /// cannot be bound. No background service is returned after a startup error.
    pub async fn start(config: RelayConfig) -> Result<RelayHandle> {
        config.validate()?;
        let tls_acceptor = build_acceptor(&config.server)?;
        let node_listener = TcpListener::bind(config.server.node_listen).await?;
        let metrics_listener = bind_metrics(config.server.metrics_listen).await?;
        let node_address = node_listener.local_addr()?;
        let metrics_address = metrics_listener.local_addr()?;
        let state = Arc::new(ServerState {
            server_config: config.server.clone(),
            configured_routes: RwLock::new(HashMap::new()),
            active_routes: RwLock::new(HashMap::new()),
            tls_acceptor,
            metrics: Metrics::default(),
            shutdown: CancellationToken::new(),
            tasks: Mutex::new(Vec::new()),
            node_address,
            metrics_address,
        });
        state.apply_routes(config.routes).await?;

        state.spawn(run_node_listener(state.clone(), node_listener));
        let metrics_state = state.clone();
        state.spawn(async move {
            if let Err(error) = serve_metrics(
                metrics_listener,
                metrics_state.metrics.clone(),
                metrics_state.shutdown.child_token(),
            )
            .await
            {
                warn!(code = error.code().as_str(), "metrics listener stopped");
            }
        });
        info!(%node_address, %metrics_address, "relay service started");
        Ok(RelayHandle { state })
    }
}

impl RelayHandle {
    #[must_use]
    pub fn node_address(&self) -> SocketAddr {
        self.state.node_address
    }

    #[must_use]
    pub fn metrics_address(&self) -> SocketAddr {
        self.state.metrics_address
    }

    pub async fn route_address(&self, route_id: &str) -> Option<SocketAddr> {
        self.state
            .active_routes
            .read()
            .await
            .get(route_id)
            .map(|route| route.public_address)
    }

    #[must_use]
    pub fn metrics(&self) -> Metrics {
        self.state.metrics.clone()
    }

    /// Applies route-only changes and revokes removed or changed route sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails, static server settings changed, or a new public
    /// route listener cannot be bound.
    pub async fn reload(&self, config: RelayConfig) -> Result<()> {
        config.validate()?;
        if config.server != self.state.server_config {
            return Err(RelayError::Config(
                "server settings changed; restart is required".to_owned(),
            ));
        }
        self.state.apply_routes(config.routes).await
    }

    /// Watches one configuration file. Invalid reloads preserve the last-known-good routes.
    pub fn watch_config(&self, path: PathBuf) {
        let handle = self.clone();
        let task_state = self.state.clone();
        let interval = self.state.server_config.reload_interval();
        self.state.spawn(async move {
            let mut last = file_fingerprint(&path).await;
            loop {
                tokio::select! {
                    () = task_state.shutdown.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                let current = file_fingerprint(&path).await;
                if current.is_some() && current != last {
                    match RelayConfig::load(&path).await.and_then(|config| {
                        if config.server == task_state.server_config {
                            Ok(config)
                        } else {
                            Err(RelayError::Config(
                                "server settings changed; restart is required".to_owned(),
                            ))
                        }
                    }) {
                        Ok(config) => match handle.reload(config).await {
                            Ok(()) => {
                                last = current;
                                info!("relay route configuration reloaded");
                            }
                            Err(error) => {
                                task_state.metrics.record_reload_failure();
                                warn!(code = error.code().as_str(), "relay route reload failed");
                            }
                        },
                        Err(error) => {
                            task_state.metrics.record_reload_failure();
                            warn!(
                                code = error.code().as_str(),
                                "relay configuration is invalid"
                            );
                        }
                    }
                }
            }
        });
    }

    pub async fn shutdown(&self) {
        self.state.shutdown.cancel();
        let routes: Vec<_> = self
            .state
            .active_routes
            .read()
            .await
            .values()
            .cloned()
            .collect();
        for route in routes {
            route.revoke();
        }
        let tasks = {
            let mut tasks = self
                .state
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *tasks)
        };
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 1 {
            self.state.shutdown.cancel();
        }
    }
}

impl ServerState {
    fn spawn<F>(&self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let task = tokio::spawn(future);
        self.tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(task);
    }

    async fn apply_routes(self: &Arc<Self>, routes: Vec<RouteConfig>) -> Result<()> {
        let next: HashMap<_, _> = routes
            .into_iter()
            .map(|route| (route.route_id.clone(), route))
            .collect();
        let existing = self.active_routes.read().await.clone();
        let changed: HashSet<String> = existing
            .iter()
            .filter(|(route_id, runtime)| next.get(*route_id) != Some(&runtime.config))
            .map(|(route_id, _runtime)| route_id.clone())
            .collect();
        let removed: HashSet<String> = existing
            .keys()
            .filter(|route_id| !next.contains_key(*route_id))
            .cloned()
            .collect();

        for route_id in changed.iter().chain(removed.iter()) {
            if let Some(runtime) = self.active_routes.write().await.remove(route_id) {
                runtime.revoke();
            }
        }
        tokio::task::yield_now().await;

        for (route_id, route) in &next {
            if !route.enabled || route.is_expired(OffsetDateTime::now_utc()) {
                continue;
            }
            if self.active_routes.read().await.contains_key(route_id) {
                continue;
            }
            let runtime = self.start_route(route.clone()).await?;
            self.active_routes
                .write()
                .await
                .insert(route_id.clone(), runtime);
        }
        *self.configured_routes.write().await = next;
        for route_id in removed {
            self.metrics.remove_route(&route_id);
        }
        Ok(())
    }

    async fn start_route(self: &Arc<Self>, config: RouteConfig) -> Result<Arc<RouteRuntime>> {
        let listener = bind_with_short_retry(config.public_listen).await?;
        let public_address = listener.local_addr()?;
        let runtime = Arc::new(RouteRuntime {
            stream_slots: Arc::new(Semaphore::new(config.max_concurrent_streams)),
            next_stream_id: AtomicU64::new(1),
            rate_limiter: RateLimiter::new(config.max_bytes_per_second),
            metrics: self.metrics.route(&config.route_id),
            cancel: self.shutdown.child_token(),
            public_address,
            server_config: self.server_config.clone(),
            config,
            tunnel: Mutex::new(None),
        });
        let task_runtime = runtime.clone();
        self.spawn(async move {
            if let Err(error) = run_route_listener(task_runtime.clone(), listener).await {
                warn!(
                    route_id = %task_runtime.config.route_id,
                    code = error.code().as_str(),
                    "public route listener stopped"
                );
            }
        });
        info!(route_id = %runtime.config.route_id, %public_address, "relay route active");
        Ok(runtime)
    }
}

impl RouteRuntime {
    fn current_tunnel(&self) -> Option<Arc<TunnelSession>> {
        self.tunnel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .filter(|tunnel| !tunnel.cancel.is_cancelled())
    }

    fn register_tunnel(&self, tunnel: Arc<TunnelSession>) {
        let old = self
            .tunnel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(tunnel);
        if let Some(old) = old {
            self.metrics
                .tunnel_replacements
                .fetch_add(1, Ordering::Relaxed);
            old.cancel.cancel();
        }
        self.metrics.active_tunnels.store(1, Ordering::Relaxed);
    }

    fn remove_tunnel(&self, tunnel_id: u64) {
        let mut current = self
            .tunnel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|tunnel| tunnel.id == tunnel_id)
        {
            current.take();
            self.metrics.active_tunnels.store(0, Ordering::Relaxed);
        }
    }

    fn revoke(&self) {
        self.cancel.cancel();
        if let Some(tunnel) = self
            .tunnel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            tunnel.cancel.cancel();
        }
        self.metrics.active_tunnels.store(0, Ordering::Relaxed);
    }
}

impl TunnelSession {
    async fn send(&self, frame: Frame) -> Result<()> {
        tokio::select! {
            () = self.cancel.cancelled() => {
                Err(RelayError::stable(ErrorCode::TunnelLost, "node tunnel is closed"))
            }
            sent = self.command_tx.send(frame) => sent.map_err(|_| {
                RelayError::stable(ErrorCode::TunnelLost, "node tunnel writer stopped")
            })
        }
    }

    async fn open_stream(
        self: &Arc<Self>,
        runtime: &RouteRuntime,
    ) -> Result<(u64, Arc<StreamDispatch>, mpsc::Receiver<Inbound>)> {
        let stream_id = runtime.next_stream_id.fetch_add(2, Ordering::Relaxed);
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(RelayError::stable(
                ErrorCode::Internal,
                "stream identifier space exhausted",
            ));
        }
        let (inbound_tx, inbound_rx) = mpsc::channel(runtime.server_config.stream_buffer_frames);
        let (open_tx, open_rx) = oneshot::channel();
        let dispatch = Arc::new(StreamDispatch {
            open_result: Mutex::new(Some(open_tx)),
            inbound_tx,
            receive_remaining: AtomicU64::new(u64::from(
                runtime.server_config.initial_window_bytes,
            )),
            send_credit: Credit::new(0),
            cancel: self.cancel.child_token(),
        });
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(stream_id, dispatch.clone());
        if let Err(error) = self
            .send(Frame::u32(
                FrameKind::Open,
                stream_id,
                runtime.server_config.initial_window_bytes,
            ))
            .await
        {
            self.remove_stream(stream_id);
            return Err(error);
        }
        let open_result = tokio::select! {
            () = self.cancel.cancelled() => {
                Err(RelayError::stable(ErrorCode::TunnelLost, "node tunnel closed while opening"))
            }
            result = tokio::time::timeout(runtime.server_config.open_timeout(), open_rx) => {
                match result {
                    Ok(Ok(Ok(window))) => Ok(window),
                    Ok(Ok(Err(code))) => Err(RelayError::stable(code, "node refused the logical stream")),
                    Ok(Err(_)) => Err(RelayError::stable(ErrorCode::TunnelLost, "node tunnel closed while opening")),
                    Err(_) => Err(RelayError::stable(ErrorCode::OpenTimeout, "node did not open the logical stream")),
                }
            }
        };
        let window = match open_result {
            Ok(window) if window > 0 => window,
            Ok(_) => {
                self.remove_stream(stream_id);
                return Err(RelayError::stable(
                    ErrorCode::ProtocolInvalid,
                    "node advertised an empty flow-control window",
                ));
            }
            Err(error) => {
                self.remove_stream(stream_id);
                return Err(error);
            }
        };
        dispatch.send_credit.add(window)?;
        Ok((stream_id, dispatch, inbound_rx))
    }

    fn remove_stream(&self, stream_id: u64) {
        if let Some(stream) = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id)
        {
            stream.cancel.cancel();
        }
    }

    fn cancel_all_streams(&self) {
        let streams = std::mem::take(
            &mut *self
                .streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for stream in streams.into_values() {
            stream.cancel.cancel();
        }
    }
}

async fn run_node_listener(state: Arc<ServerState>, listener: TcpListener) {
    let connection_slots = Arc::new(Semaphore::new(state.server_config.max_node_connections));
    loop {
        let (mut socket, _peer) = tokio::select! {
            () = state.shutdown.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(code = ErrorCode::Internal.as_str(), %error, "node listener accept failed");
                    continue;
                }
            }
        };
        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
            let _ = socket.shutdown().await;
            continue;
        };
        let task_state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_node_connection(task_state.clone(), socket).await {
                if matches!(
                    error.code(),
                    ErrorCode::AuthFailed | ErrorCode::RouteUnknown
                ) {
                    task_state.metrics.record_auth_failure();
                } else if matches!(
                    error.code(),
                    ErrorCode::ProtocolInvalid | ErrorCode::FrameTooLarge
                ) {
                    task_state.metrics.record_protocol_failure();
                }
                warn!(
                    code = error.code().as_str(),
                    "node tunnel rejected or closed"
                );
            }
        });
    }
}

async fn handle_node_connection(state: Arc<ServerState>, socket: TcpStream) -> Result<()> {
    socket.set_nodelay(true)?;
    let mut tls = tokio::time::timeout(
        state.server_config.open_timeout(),
        state.tls_acceptor.accept(socket),
    )
    .await
    .map_err(|_| RelayError::stable(ErrorCode::OpenTimeout, "TLS handshake timed out"))?
    .map_err(|error| RelayError::Tls(format!("TLS handshake failed: {error}")))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"pn-relay-v1".as_slice()) {
        return Err(RelayError::stable(
            ErrorCode::ProtocolInvalid,
            "required relay ALPN was not negotiated",
        ));
    }
    let peer_certificate = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| RelayError::stable(ErrorCode::AuthFailed, "node certificate is missing"))?;
    let cert_digest = certificate_sha256(peer_certificate);
    let mut register = tokio::time::timeout(
        state.server_config.open_timeout(),
        Frame::read_from(&mut tls, state.server_config.max_frame_bytes),
    )
    .await
    .map_err(|_| RelayError::stable(ErrorCode::OpenTimeout, "route registration timed out"))??
    .ok_or_else(|| {
        RelayError::stable(ErrorCode::ProtocolInvalid, "route registration is missing")
    })?;
    let (route_id, token) = register.parse_register()?;
    if token.is_empty() || token.len() > REGISTER_TOKEN_MAX_BYTES {
        register.payload.zeroize();
        write_terminal_error(&mut tls, &state.server_config, ErrorCode::AuthFailed).await;
        return Err(RelayError::stable(
            ErrorCode::AuthFailed,
            "route authentication failed",
        ));
    }
    let route_id = route_id.to_owned();
    let token_digest: [u8; 32] = Sha256::digest(token).into();
    register.payload.zeroize();
    let route_config = state.configured_routes.read().await.get(&route_id).cloned();
    let Some(route_config) = route_config else {
        write_terminal_error(&mut tls, &state.server_config, ErrorCode::RouteUnknown).await;
        return Err(RelayError::stable(
            ErrorCode::RouteUnknown,
            "route is not configured",
        ));
    };
    if !route_config.enabled {
        write_terminal_error(&mut tls, &state.server_config, ErrorCode::RouteRevoked).await;
        return Err(RelayError::stable(
            ErrorCode::RouteRevoked,
            "route is disabled",
        ));
    }
    if route_config.is_expired(OffsetDateTime::now_utc()) {
        write_terminal_error(&mut tls, &state.server_config, ErrorCode::GrantExpired).await;
        return Err(RelayError::stable(
            ErrorCode::GrantExpired,
            "route grant expired",
        ));
    }
    if !route_config.token_matches(&token_digest) || !route_config.cert_matches(&cert_digest) {
        write_terminal_error(&mut tls, &state.server_config, ErrorCode::AuthFailed).await;
        return Err(RelayError::stable(
            ErrorCode::AuthFailed,
            "route authentication failed",
        ));
    }
    let runtime = state
        .active_routes
        .read()
        .await
        .get(&route_id)
        .cloned()
        .ok_or_else(|| {
            RelayError::stable(ErrorCode::RouteUnavailable, "route listener is unavailable")
        })?;
    run_tunnel(runtime, tls).await
}

async fn write_terminal_error(
    tls: &mut TlsStream<TcpStream>,
    config: &ServerConfig,
    code: ErrorCode,
) {
    let _ = Frame::code(FrameKind::Error, 0, code)
        .write_to(tls, config.max_frame_bytes)
        .await;
    let _ = tls.shutdown().await;
}

async fn run_tunnel(runtime: Arc<RouteRuntime>, tls: TlsStream<TcpStream>) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(tls);
    let (command_tx, mut command_rx) = mpsc::channel(runtime.server_config.command_queue_frames);
    let tunnel = Arc::new(TunnelSession {
        id: random_session_id(),
        command_tx,
        streams: Arc::new(Mutex::new(HashMap::new())),
        last_pong: Mutex::new(Instant::now()),
        cancel: runtime.cancel.child_token(),
    });
    runtime.register_tunnel(tunnel.clone());
    tunnel
        .send(Frame::u32(
            FrameKind::RegisterOk,
            0,
            u32::try_from(runtime.server_config.heartbeat_interval_secs).unwrap_or(u32::MAX),
        ))
        .await?;

    let writer_tunnel = tunnel.clone();
    let max_frame_bytes = runtime.server_config.max_frame_bytes;
    let writer_task: JoinHandle<Result<()>> = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = writer_tunnel.cancel.cancelled() => return Ok(()),
                frame = command_rx.recv() => match frame {
                    Some(frame) => frame.write_to(&mut writer, max_frame_bytes).await?,
                    None => return Ok(()),
                }
            }
        }
    });
    let heartbeat_task = tokio::spawn(run_heartbeat(tunnel.clone(), runtime.clone()));
    let read_result = read_tunnel_frames(&mut reader, tunnel.clone(), runtime.clone()).await;
    tunnel.cancel.cancel();
    tunnel.cancel_all_streams();
    runtime.remove_tunnel(tunnel.id);
    let _ = writer_task.await;
    let _ = heartbeat_task.await;
    read_result
}

#[allow(clippy::too_many_lines)] // One exhaustive frame-direction table makes tunnel validation auditable.
async fn read_tunnel_frames(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    tunnel: Arc<TunnelSession>,
    runtime: Arc<RouteRuntime>,
) -> Result<()> {
    loop {
        let frame = tokio::select! {
            () = tunnel.cancel.cancelled() => return Ok(()),
            frame = Frame::read_from(reader, runtime.server_config.max_frame_bytes) => {
                frame?.ok_or_else(|| RelayError::stable(ErrorCode::TunnelLost, "node tunnel reached EOF"))?
            }
        };
        match frame.kind {
            FrameKind::OpenOk => {
                let window = frame.parse_u32()?;
                let dispatch = stream_dispatch(&tunnel, frame.stream_id)?;
                let sender = dispatch
                    .open_result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .ok_or_else(|| {
                        RelayError::stable(
                            ErrorCode::ProtocolInvalid,
                            "duplicate stream open result",
                        )
                    })?;
                let _ = sender.send(Ok(window));
            }
            FrameKind::OpenError => {
                let dispatch = stream_dispatch(&tunnel, frame.stream_id)?;
                let sender = dispatch
                    .open_result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(sender) = sender {
                    let _ = sender.send(Err(ErrorCode::RouteUnavailable));
                }
            }
            FrameKind::Data => {
                let dispatch = stream_dispatch(&tunnel, frame.stream_id)?;
                debit_receive_window(&dispatch, frame.payload.len())?;
                if dispatch
                    .inbound_tx
                    .try_send(Inbound::Data(frame.payload))
                    .is_err()
                {
                    tunnel
                        .send(Frame::code(
                            FrameKind::Close,
                            frame.stream_id,
                            ErrorCode::LimitReached,
                        ))
                        .await?;
                    tunnel.remove_stream(frame.stream_id);
                }
            }
            FrameKind::Fin => {
                let dispatch = stream_dispatch(&tunnel, frame.stream_id)?;
                if dispatch.inbound_tx.try_send(Inbound::Fin).is_err() {
                    tunnel.remove_stream(frame.stream_id);
                }
            }
            FrameKind::Close => {
                if let Ok(dispatch) = stream_dispatch(&tunnel, frame.stream_id) {
                    let _ = dispatch.inbound_tx.try_send(Inbound::Close);
                }
                tunnel.remove_stream(frame.stream_id);
            }
            FrameKind::WindowUpdate => {
                let dispatch = stream_dispatch(&tunnel, frame.stream_id)?;
                dispatch.send_credit.add(frame.parse_u32()?)?;
            }
            FrameKind::Ping => {
                if frame.stream_id != 0 || frame.payload.len() != 8 {
                    return Err(RelayError::stable(
                        ErrorCode::ProtocolInvalid,
                        "invalid heartbeat frame",
                    ));
                }
                tunnel
                    .send(Frame::new(FrameKind::Pong, 0, frame.payload))
                    .await?;
            }
            FrameKind::Pong => {
                if frame.stream_id != 0 || frame.payload.len() != 8 {
                    return Err(RelayError::stable(
                        ErrorCode::ProtocolInvalid,
                        "invalid heartbeat frame",
                    ));
                }
                *tunnel
                    .last_pong
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
            }
            FrameKind::Register | FrameKind::RegisterOk | FrameKind::Error | FrameKind::Open => {
                return Err(RelayError::stable(
                    ErrorCode::ProtocolInvalid,
                    "frame kind is invalid in this direction",
                ));
            }
        }
    }
}

async fn run_heartbeat(tunnel: Arc<TunnelSession>, runtime: Arc<RouteRuntime>) {
    let mut sequence = 0_u64;
    loop {
        tokio::select! {
            () = tunnel.cancel.cancelled() => return,
            () = tokio::time::sleep(runtime.server_config.heartbeat_interval()) => {}
        }
        if runtime.config.is_expired(OffsetDateTime::now_utc())
            || tunnel
                .last_pong
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .elapsed()
                > runtime.server_config.heartbeat_timeout()
        {
            tunnel.cancel.cancel();
            return;
        }
        sequence = sequence.wrapping_add(1);
        if tunnel
            .send(Frame::new(
                FrameKind::Ping,
                0,
                sequence.to_be_bytes().to_vec(),
            ))
            .await
            .is_err()
        {
            tunnel.cancel.cancel();
            return;
        }
    }
}

fn stream_dispatch(tunnel: &TunnelSession, stream_id: u64) -> Result<Arc<StreamDispatch>> {
    if stream_id == 0 || stream_id.is_multiple_of(2) {
        return Err(RelayError::stable(
            ErrorCode::ProtocolInvalid,
            "node used an invalid stream identifier",
        ));
    }
    tunnel
        .streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&stream_id)
        .cloned()
        .ok_or_else(|| RelayError::stable(ErrorCode::ProtocolInvalid, "stream is not open"))
}

fn debit_receive_window(dispatch: &StreamDispatch, bytes: usize) -> Result<()> {
    let bytes = u64::try_from(bytes).map_err(|_| {
        RelayError::stable(ErrorCode::ProtocolInvalid, "payload length is unsupported")
    })?;
    dispatch
        .receive_remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(bytes)
        })
        .map(|_| ())
        .map_err(|_| {
            RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "node exceeded the stream receive window",
            )
        })
}

async fn run_route_listener(runtime: Arc<RouteRuntime>, listener: TcpListener) -> Result<()> {
    loop {
        let (mut socket, _peer) = tokio::select! {
            () = runtime.cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let Ok(permit) = runtime.stream_slots.clone().try_acquire_owned() else {
            runtime
                .metrics
                .refused_streams
                .fetch_add(1, Ordering::Relaxed);
            socket.shutdown().await?;
            continue;
        };
        let task_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_member(task_runtime.clone(), socket, permit).await {
                task_runtime
                    .metrics
                    .refused_streams
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    route_id = %task_runtime.config.route_id,
                    code = error.code().as_str(),
                    "relay member stream closed"
                );
            }
        });
    }
}

async fn handle_member(
    runtime: Arc<RouteRuntime>,
    mut socket: TcpStream,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    socket.set_nodelay(true)?;
    if runtime.config.is_expired(OffsetDateTime::now_utc()) {
        socket.shutdown().await?;
        return Err(RelayError::stable(
            ErrorCode::GrantExpired,
            "route grant expired",
        ));
    }
    let tunnel = runtime.current_tunnel().ok_or_else(|| {
        RelayError::stable(ErrorCode::RouteUnavailable, "node tunnel is unavailable")
    })?;
    let (stream_id, dispatch, inbound_rx) = tunnel.open_stream(&runtime).await?;
    runtime
        .metrics
        .accepted_streams
        .fetch_add(1, Ordering::Relaxed);
    runtime
        .metrics
        .active_streams
        .fetch_add(1, Ordering::Relaxed);
    let active_guard = ActiveStreamGuard {
        metrics: runtime.metrics.clone(),
        _permit: permit,
    };
    let result =
        relay_member_stream(&runtime, &tunnel, stream_id, dispatch, inbound_rx, socket).await;
    tunnel.remove_stream(stream_id);
    let _ = tunnel
        .send(Frame::code(
            FrameKind::Close,
            stream_id,
            result_code(&result),
        ))
        .await;
    drop(active_guard);
    result
}

async fn relay_member_stream(
    runtime: &Arc<RouteRuntime>,
    tunnel: &Arc<TunnelSession>,
    stream_id: u64,
    dispatch: Arc<StreamDispatch>,
    inbound_rx: mpsc::Receiver<Inbound>,
    socket: TcpStream,
) -> Result<()> {
    let activity = Arc::new(Activity {
        started: Instant::now(),
        last_payload: Mutex::new(Instant::now()),
        bytes: AtomicU64::new(0),
    });
    let connection_bytes = Arc::new(AtomicU64::new(0));
    let (reader, writer) = tokio::io::split(socket);
    let upload = pump_member_to_node(
        runtime.clone(),
        tunnel.clone(),
        stream_id,
        dispatch.clone(),
        reader,
        activity.clone(),
        connection_bytes.clone(),
    );
    let download = pump_node_to_member(
        runtime.clone(),
        tunnel.clone(),
        stream_id,
        dispatch.clone(),
        inbound_rx,
        writer,
        activity.clone(),
        connection_bytes,
    );
    let watchdog = watch_stream(runtime.clone(), dispatch.clone(), activity);
    tokio::pin!(upload, download, watchdog);
    let result = tokio::select! {
        result = async { tokio::try_join!(upload, download).map(|_| ()) } => result,
        result = &mut watchdog => result,
        () = dispatch.cancel.cancelled() => {
            Err(RelayError::stable(ErrorCode::TunnelLost, "logical stream was cancelled"))
        }
    };
    dispatch.cancel.cancel();
    result
}

#[allow(clippy::too_many_arguments)]
async fn pump_member_to_node(
    runtime: Arc<RouteRuntime>,
    tunnel: Arc<TunnelSession>,
    stream_id: u64,
    dispatch: Arc<StreamDispatch>,
    mut reader: ReadHalf<TcpStream>,
    activity: Arc<Activity>,
    connection_bytes: Arc<AtomicU64>,
) -> Result<()> {
    let mut buffer = vec![0_u8; runtime.server_config.max_frame_bytes];
    loop {
        let read = tokio::select! {
            () = dispatch.cancel.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => read?,
        };
        if read == 0 {
            tunnel
                .send(Frame::new(FrameKind::Fin, stream_id, Vec::new()))
                .await?;
            return Ok(());
        }
        account_connection_bytes(&runtime, &connection_bytes, read)?;
        runtime.rate_limiter.acquire(read, &dispatch.cancel).await?;
        dispatch.send_credit.consume(read, &dispatch.cancel).await?;
        tunnel
            .send(Frame::new(
                FrameKind::Data,
                stream_id,
                buffer[..read].to_vec(),
            ))
            .await?;
        record_activity(&activity, read);
        runtime
            .metrics
            .bytes_member_to_node
            .fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_node_to_member(
    runtime: Arc<RouteRuntime>,
    tunnel: Arc<TunnelSession>,
    stream_id: u64,
    dispatch: Arc<StreamDispatch>,
    mut inbound_rx: mpsc::Receiver<Inbound>,
    mut writer: WriteHalf<TcpStream>,
    activity: Arc<Activity>,
    connection_bytes: Arc<AtomicU64>,
) -> Result<()> {
    loop {
        let inbound = tokio::select! {
            () = dispatch.cancel.cancelled() => return Ok(()),
            inbound = inbound_rx.recv() => inbound.ok_or_else(|| {
                RelayError::stable(ErrorCode::TunnelLost, "logical stream channel closed")
            })?,
        };
        match inbound {
            Inbound::Data(bytes) => {
                account_connection_bytes(&runtime, &connection_bytes, bytes.len())?;
                runtime
                    .rate_limiter
                    .acquire(bytes.len(), &dispatch.cancel)
                    .await?;
                writer.write_all(&bytes).await?;
                let amount = u32::try_from(bytes.len()).map_err(|_| {
                    RelayError::stable(
                        ErrorCode::FrameTooLarge,
                        "payload cannot update flow window",
                    )
                })?;
                dispatch
                    .receive_remaining
                    .fetch_add(u64::from(amount), Ordering::Release);
                tunnel
                    .send(Frame::u32(FrameKind::WindowUpdate, stream_id, amount))
                    .await?;
                record_activity(&activity, bytes.len());
                runtime
                    .metrics
                    .bytes_node_to_member
                    .fetch_add(u64::from(amount), Ordering::Relaxed);
            }
            Inbound::Fin => {
                writer.shutdown().await?;
                return Ok(());
            }
            Inbound::Close => {
                return Err(RelayError::stable(
                    ErrorCode::TunnelLost,
                    "node closed the logical stream",
                ));
            }
        }
    }
}

async fn watch_stream(
    runtime: Arc<RouteRuntime>,
    dispatch: Arc<StreamDispatch>,
    activity: Arc<Activity>,
) -> Result<()> {
    loop {
        tokio::select! {
            () = dispatch.cancel.cancelled() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        let idle = activity
            .last_payload
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed();
        if activity.bytes.load(Ordering::Relaxed) == 0
            && activity.started.elapsed() > runtime.server_config.no_payload_timeout()
        {
            return Err(RelayError::stable(
                ErrorCode::IdleTimeout,
                "stream sent no payload before the deadline",
            ));
        }
        if idle > runtime.server_config.idle_timeout() {
            return Err(RelayError::stable(
                ErrorCode::IdleTimeout,
                "stream exceeded its idle timeout",
            ));
        }
        if runtime.config.is_expired(OffsetDateTime::now_utc()) {
            return Err(RelayError::stable(
                ErrorCode::GrantExpired,
                "route grant expired",
            ));
        }
    }
}

fn account_connection_bytes(
    runtime: &RouteRuntime,
    connection_bytes: &AtomicU64,
    amount: usize,
) -> Result<()> {
    let amount = u64::try_from(amount).map_err(|_| {
        RelayError::stable(ErrorCode::LimitReached, "connection byte count overflow")
    })?;
    connection_bytes
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(amount)
                .filter(|next| *next <= runtime.config.max_bytes_per_connection)
        })
        .map(|_| ())
        .map_err(|_| RelayError::stable(ErrorCode::LimitReached, "connection byte limit reached"))
}

fn record_activity(activity: &Activity, amount: usize) {
    activity
        .bytes
        .fetch_add(u64::try_from(amount).unwrap_or(u64::MAX), Ordering::Relaxed);
    *activity
        .last_payload
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
}

fn result_code(result: &Result<()>) -> ErrorCode {
    result
        .as_ref()
        .err()
        .map_or(ErrorCode::TunnelLost, RelayError::code)
}

struct ActiveStreamGuard {
    metrics: Arc<RouteMetrics>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ActiveStreamGuard {
    fn drop(&mut self) {
        self.metrics.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn bind_with_short_retry(address: SocketAddr) -> Result<TcpListener> {
    let mut last_error = None;
    for _ in 0..10 {
        match TcpListener::bind(address).await {
            Ok(listener) => return Ok(listener),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("listener bind retry failed"))
        .into())
}

async fn file_fingerprint(path: &PathBuf) -> Option<(u64, std::time::SystemTime)> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
}

fn random_session_id() -> u64 {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_and_connection_limits_are_bounded() {
        let counter = AtomicU64::new(0);
        let runtime = RouteRuntime {
            config: RouteConfig {
                route_id: "route_0123456789abcdef".to_owned(),
                public_listen: "127.0.0.1:0".parse().unwrap(),
                node_token_sha256: "11".repeat(32),
                node_cert_sha256: "22".repeat(32),
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                enabled: true,
                max_concurrent_streams: 1,
                max_bytes_per_second: 1_024,
                max_bytes_per_connection: 1_024,
            },
            public_address: "127.0.0.1:1".parse().unwrap(),
            server_config: test_server_config(),
            tunnel: Mutex::new(None),
            stream_slots: Arc::new(Semaphore::new(1)),
            next_stream_id: AtomicU64::new(1),
            rate_limiter: RateLimiter::new(1_024),
            metrics: Arc::new(RouteMetrics::default()),
            cancel: CancellationToken::new(),
        };
        account_connection_bytes(&runtime, &counter, 1_024).unwrap();
        assert_eq!(
            account_connection_bytes(&runtime, &counter, 1)
                .unwrap_err()
                .code(),
            ErrorCode::LimitReached
        );
    }

    fn test_server_config() -> ServerConfig {
        ServerConfig {
            node_listen: "127.0.0.1:0".parse().unwrap(),
            metrics_listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert_path: "server.pem".into(),
            tls_key_path: "server-key.pem".into(),
            client_ca_path: "ca.pem".into(),
            max_frame_bytes: 1_024,
            command_queue_frames: 4,
            stream_buffer_frames: 2,
            initial_window_bytes: 1_024,
            open_timeout_secs: 1,
            no_payload_timeout_secs: 1,
            idle_timeout_secs: 2,
            heartbeat_interval_secs: 1,
            heartbeat_timeout_secs: 2,
            reload_interval_secs: 1,
            max_routes: 1,
            max_node_connections: 1,
        }
    }
}
