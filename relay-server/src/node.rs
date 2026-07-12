use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    error::{ErrorCode, RelayError, Result},
    flow::Credit,
    frame::{Frame, FrameKind},
    tls::{
        enforce_private_file_permissions, ensure_crypto_provider, load_certificates,
        load_private_key,
    },
};

const MIN_ROUTE_TOKEN_BYTES: usize = 32;
const MAX_ROUTE_TOKEN_BYTES: usize = 256;
const MIN_FRAME_BYTES: usize = 1_024;
const MAX_FRAME_BYTES: usize = 1_048_576;

/// Configuration for the node-originated side of one relay route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeConnectorConfig {
    pub relay_address: SocketAddr,
    pub relay_server_name: String,
    pub route_id: String,
    pub route_token_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub relay_ca_path: PathBuf,
    pub local_target: SocketAddr,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_command_queue_frames")]
    pub command_queue_frames: usize,
    #[serde(default = "default_stream_buffer_frames")]
    pub stream_buffer_frames: usize,
    #[serde(default = "default_initial_window_bytes")]
    pub initial_window_bytes: u32,
    #[serde(default = "default_max_streams")]
    pub max_streams: usize,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_reconnect_initial_ms")]
    pub reconnect_initial_ms: u64,
    #[serde(default = "default_reconnect_max_secs")]
    pub reconnect_max_secs: u64,
}

impl NodeConnectorConfig {
    /// Loads and validates a connector TOML file, resolving relative paths against its directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable/invalid TOML or a configuration that permits a non-loopback
    /// target, unbounded queues, malformed route identity, or inconsistent timeouts.
    pub async fn load(path: &Path) -> Result<Self> {
        let bytes = tokio::fs::read(path).await.map_err(|error| {
            RelayError::Config(format!("cannot read {}: {error}", path.display()))
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| RelayError::Config("connector configuration is not UTF-8".to_owned()))?;
        let mut config: Self = toml::from_str(text)
            .map_err(|error| RelayError::Config(format!("invalid connector TOML: {error}")))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for candidate in [
            &mut config.route_token_path,
            &mut config.tls_cert_path,
            &mut config.tls_key_path,
            &mut config.relay_ca_path,
        ] {
            if candidate.is_relative() {
                *candidate = base.join(&*candidate);
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Validates connector bounds and the fixed loopback target invariant.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector could target a remote/arbitrary service, allocate an
    /// unbounded queue, or use inconsistent flow-control, heartbeat, and backoff limits.
    pub fn validate(&self) -> Result<()> {
        if self.relay_address.port() == 0 {
            return Err(RelayError::Config(
                "relay_address must use a non-zero port".to_owned(),
            ));
        }
        if !self.local_target.ip().is_loopback() || self.local_target.port() == 0 {
            return Err(RelayError::Config(
                "local_target must be a fixed loopback TCP address with a non-zero port".to_owned(),
            ));
        }
        if self.route_id.len() < 16
            || self.route_id.len() > 128
            || !self
                .route_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(RelayError::Config(
                "route_id must be 16-128 ASCII URL-safe characters".to_owned(),
            ));
        }
        if self.relay_server_name.is_empty() || self.relay_server_name.len() > 253 {
            return Err(RelayError::Config(
                "relay_server_name must be a bounded DNS name or IP address".to_owned(),
            ));
        }
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&self.max_frame_bytes)
            || self.command_queue_frames == 0
            || self.stream_buffer_frames == 0
            || self.max_streams == 0
            || usize::try_from(self.initial_window_bytes)
                .map_or(true, |window| window < self.max_frame_bytes)
        {
            return Err(RelayError::Config(
                "connector frame, queue, stream, or flow-control bounds are invalid".to_owned(),
            ));
        }
        if self.connect_timeout_secs == 0
            || self.idle_timeout_secs == 0
            || self.heartbeat_interval_secs == 0
            || self.heartbeat_timeout_secs <= self.heartbeat_interval_secs
            || self.reconnect_initial_ms == 0
            || self.reconnect_max_secs == 0
            || Duration::from_millis(self.reconnect_initial_ms)
                > Duration::from_secs(self.reconnect_max_secs)
        {
            return Err(RelayError::Config(
                "connector timeouts and reconnect backoff are inconsistent".to_owned(),
            ));
        }
        Ok(())
    }

    fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }

    fn heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(self.heartbeat_timeout_secs)
    }

    fn reconnect_initial(&self) -> Duration {
        Duration::from_millis(self.reconnect_initial_ms)
    }

    fn reconnect_max(&self) -> Duration {
        Duration::from_secs(self.reconnect_max_secs)
    }
}

/// Redacted connector lifecycle state suitable for Node Host status reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectorStatus {
    Disconnected,
    Connecting,
    Registered,
    Backoff { delay: Duration },
    Stopped,
}

/// Reusable node connector for one fixed relay route and one loopback Xray target.
pub struct RelayNodeConnector {
    config: Arc<NodeConnectorConfig>,
    tls_config: Arc<ClientConfig>,
    route_token: Zeroizing<Vec<u8>>,
    status_tx: watch::Sender<ConnectorStatus>,
}

struct NodeTunnel {
    command_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u64, Arc<NodeStream>>>>,
    last_pong: Mutex<Instant>,
    cancel: CancellationToken,
}

struct NodeStream {
    inbound_tx: mpsc::Sender<NodeInbound>,
    receive_remaining: AtomicU64,
    send_credit: Credit,
    cancel: CancellationToken,
}

enum NodeInbound {
    Data(Vec<u8>),
    Fin,
    Close,
}

impl RelayNodeConnector {
    /// Loads private route material and constructs a connector without opening a socket.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, insecure private-file permissions, malformed
    /// TLS material, or a route token outside the supported bounded ASCII representation.
    pub async fn new(config: NodeConnectorConfig) -> Result<Self> {
        config.validate()?;
        let tls_config = build_client_config(&config)?;
        enforce_private_file_permissions(&config.route_token_path)?;
        let token = tokio::fs::read(&config.route_token_path)
            .await
            .map_err(|error| {
                RelayError::Config(format!(
                    "cannot read route token {}: {error}",
                    config.route_token_path.display()
                ))
            })?;
        let token = trim_one_line_ending(token);
        if !(MIN_ROUTE_TOKEN_BYTES..=MAX_ROUTE_TOKEN_BYTES).contains(&token.len())
            || !token
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(RelayError::Config(
                "route token must be 32-256 ASCII URL-safe characters".to_owned(),
            ));
        }
        let (status_tx, _status_rx) = watch::channel(ConnectorStatus::Disconnected);
        Ok(Self {
            config: Arc::new(config),
            tls_config,
            route_token: Zeroizing::new(token),
            status_tx,
        })
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ConnectorStatus> {
        self.status_tx.subscribe()
    }

    /// Runs the connector until cancellation, reconnecting with capped exponential backoff.
    pub async fn run(&self, shutdown: CancellationToken) {
        let mut backoff =
            Backoff::new(self.config.reconnect_initial(), self.config.reconnect_max());
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            self.status_tx.send_replace(ConnectorStatus::Connecting);
            let connected_at = Instant::now();
            let result = self.run_session(shutdown.child_token()).await;
            if shutdown.is_cancelled() {
                break;
            }
            if connected_at.elapsed() >= self.config.heartbeat_timeout() {
                backoff.reset();
            }
            let delay = backoff.next_delay();
            self.status_tx
                .send_replace(ConnectorStatus::Backoff { delay });
            if let Err(error) = result {
                warn!(
                    route_id = %self.config.route_id,
                    code = error.code().as_str(),
                    "relay node session ended"
                );
            }
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(delay) => {}
            }
        }
        self.status_tx.send_replace(ConnectorStatus::Stopped);
    }

    async fn run_session(&self, shutdown: CancellationToken) -> Result<()> {
        let socket = tokio::time::timeout(
            self.config.connect_timeout(),
            TcpStream::connect(self.config.relay_address),
        )
        .await
        .map_err(|_| RelayError::stable(ErrorCode::OpenTimeout, "relay TCP connect timed out"))??;
        socket.set_nodelay(true)?;
        let server_name = ServerName::try_from(self.config.relay_server_name.clone())
            .map_err(|_| RelayError::Config("relay_server_name is invalid".to_owned()))?;
        let mut tls = tokio::time::timeout(
            self.config.connect_timeout(),
            TlsConnector::from(self.tls_config.clone()).connect(server_name, socket),
        )
        .await
        .map_err(|_| RelayError::stable(ErrorCode::OpenTimeout, "relay TLS handshake timed out"))?
        .map_err(|error| RelayError::Tls(format!("relay TLS handshake failed: {error}")))?;
        if tls.get_ref().1.alpn_protocol() != Some(b"pn-relay-v1".as_slice()) {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "required relay ALPN was not negotiated",
            ));
        }
        let mut register = Frame::register(&self.config.route_id, self.route_token.as_slice())?;
        let write_result = register
            .write_to(&mut tls, self.config.max_frame_bytes)
            .await;
        register.payload.zeroize();
        write_result?;
        let response = tokio::time::timeout(
            self.config.connect_timeout(),
            Frame::read_from(&mut tls, self.config.max_frame_bytes),
        )
        .await
        .map_err(|_| RelayError::stable(ErrorCode::OpenTimeout, "relay registration timed out"))??
        .ok_or_else(|| RelayError::stable(ErrorCode::TunnelLost, "relay closed registration"))?;
        match response.kind {
            FrameKind::RegisterOk if response.stream_id == 0 => {
                response.parse_u32()?;
            }
            FrameKind::Error if response.stream_id == 0 => {
                let code = ErrorCode::from_wire(&response.payload).unwrap_or(ErrorCode::Internal);
                return Err(RelayError::stable(
                    code,
                    "relay rejected route registration",
                ));
            }
            _ => {
                return Err(RelayError::stable(
                    ErrorCode::ProtocolInvalid,
                    "relay returned an invalid registration response",
                ));
            }
        }
        self.status_tx.send_replace(ConnectorStatus::Registered);
        info!(route_id = %self.config.route_id, "relay node route registered");
        serve_node_tunnel(self.config.clone(), tls, shutdown).await
    }
}

impl NodeTunnel {
    async fn send(&self, frame: Frame) -> Result<()> {
        tokio::select! {
            () = self.cancel.cancelled() => {
                Err(RelayError::stable(ErrorCode::TunnelLost, "relay tunnel is closed"))
            }
            result = self.command_tx.send(frame) => result.map_err(|_| {
                RelayError::stable(ErrorCode::TunnelLost, "relay tunnel writer stopped")
            })
        }
    }

    fn stream(&self, stream_id: u64) -> Result<Arc<NodeStream>> {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "relay used an invalid stream identifier",
            ));
        }
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&stream_id)
            .cloned()
            .ok_or_else(|| RelayError::stable(ErrorCode::ProtocolInvalid, "stream is not open"))
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

    fn cancel_all(&self) {
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

async fn serve_node_tunnel(
    config: Arc<NodeConnectorConfig>,
    tls: TlsStream<TcpStream>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(tls);
    let (command_tx, mut command_rx) = mpsc::channel(config.command_queue_frames);
    let tunnel = Arc::new(NodeTunnel {
        command_tx,
        streams: Arc::new(Mutex::new(HashMap::new())),
        last_pong: Mutex::new(Instant::now()),
        cancel: shutdown.child_token(),
    });
    let stream_slots = Arc::new(Semaphore::new(config.max_streams));
    let writer_tunnel = tunnel.clone();
    let max_frame_bytes = config.max_frame_bytes;
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
    let heartbeat_task = tokio::spawn(run_node_heartbeat(tunnel.clone(), config.clone()));
    let read_result = read_relay_frames(&mut reader, tunnel.clone(), config, stream_slots).await;
    tunnel.cancel.cancel();
    tunnel.cancel_all();
    let _ = writer_task.await;
    let _ = heartbeat_task.await;
    read_result
}

#[allow(clippy::too_many_lines)] // Keeping the exhaustive direction/state validation in one dispatch table is safer.
async fn read_relay_frames(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    tunnel: Arc<NodeTunnel>,
    config: Arc<NodeConnectorConfig>,
    stream_slots: Arc<Semaphore>,
) -> Result<()> {
    loop {
        let frame = tokio::select! {
            () = tunnel.cancel.cancelled() => return Ok(()),
            frame = Frame::read_from(reader, config.max_frame_bytes) => {
                frame?.ok_or_else(|| RelayError::stable(ErrorCode::TunnelLost, "relay tunnel reached EOF"))?
            }
        };
        match frame.kind {
            FrameKind::Open => {
                let peer_window = frame.parse_u32()?;
                if peer_window == 0 || frame.stream_id == 0 || frame.stream_id.is_multiple_of(2) {
                    return Err(RelayError::stable(
                        ErrorCode::ProtocolInvalid,
                        "relay sent an invalid stream open",
                    ));
                }
                let Ok(permit) = stream_slots.clone().try_acquire_owned() else {
                    tunnel
                        .send(Frame::code(
                            FrameKind::OpenError,
                            frame.stream_id,
                            ErrorCode::LimitReached,
                        ))
                        .await?;
                    continue;
                };
                let (inbound_tx, inbound_rx) = mpsc::channel(config.stream_buffer_frames);
                let stream = Arc::new(NodeStream {
                    inbound_tx,
                    receive_remaining: AtomicU64::new(u64::from(config.initial_window_bytes)),
                    send_credit: Credit::new(peer_window),
                    cancel: tunnel.cancel.child_token(),
                });
                if tunnel
                    .streams
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(frame.stream_id, stream.clone())
                    .is_some()
                {
                    return Err(RelayError::stable(
                        ErrorCode::ProtocolInvalid,
                        "relay reused an open stream identifier",
                    ));
                }
                tokio::spawn(run_local_stream(
                    tunnel.clone(),
                    stream,
                    config.clone(),
                    frame.stream_id,
                    inbound_rx,
                    permit,
                ));
            }
            FrameKind::Data => {
                let stream = tunnel.stream(frame.stream_id)?;
                debit_window(&stream, frame.payload.len())?;
                if stream
                    .inbound_tx
                    .try_send(NodeInbound::Data(frame.payload))
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
                let stream = tunnel.stream(frame.stream_id)?;
                if stream.inbound_tx.try_send(NodeInbound::Fin).is_err() {
                    tunnel.remove_stream(frame.stream_id);
                }
            }
            FrameKind::Close => {
                if let Ok(stream) = tunnel.stream(frame.stream_id) {
                    let _ = stream.inbound_tx.try_send(NodeInbound::Close);
                }
                tunnel.remove_stream(frame.stream_id);
            }
            FrameKind::WindowUpdate => {
                let stream = tunnel.stream(frame.stream_id)?;
                stream.send_credit.add(frame.parse_u32()?)?;
            }
            FrameKind::Ping => {
                if frame.stream_id != 0 || frame.payload.len() != 8 {
                    return Err(RelayError::stable(
                        ErrorCode::ProtocolInvalid,
                        "relay heartbeat is invalid",
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
                        "relay heartbeat is invalid",
                    ));
                }
                *tunnel
                    .last_pong
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
            }
            FrameKind::Error => {
                let code = ErrorCode::from_wire(&frame.payload).unwrap_or(ErrorCode::Internal);
                return Err(RelayError::stable(code, "relay closed the tunnel"));
            }
            FrameKind::Register
            | FrameKind::RegisterOk
            | FrameKind::OpenOk
            | FrameKind::OpenError => {
                return Err(RelayError::stable(
                    ErrorCode::ProtocolInvalid,
                    "frame kind is invalid in this direction",
                ));
            }
        }
    }
}

async fn run_local_stream(
    tunnel: Arc<NodeTunnel>,
    stream: Arc<NodeStream>,
    config: Arc<NodeConnectorConfig>,
    stream_id: u64,
    inbound_rx: mpsc::Receiver<NodeInbound>,
    _permit: OwnedSemaphorePermit,
) {
    let target = tokio::time::timeout(
        config.connect_timeout(),
        TcpStream::connect(config.local_target),
    )
    .await;
    let Ok(Ok(target)) = target else {
        let _ = tunnel
            .send(Frame::code(
                FrameKind::OpenError,
                stream_id,
                ErrorCode::RouteUnavailable,
            ))
            .await;
        tunnel.remove_stream(stream_id);
        return;
    };
    if target.set_nodelay(true).is_err()
        || tunnel
            .send(Frame::u32(
                FrameKind::OpenOk,
                stream_id,
                config.initial_window_bytes,
            ))
            .await
            .is_err()
    {
        tunnel.remove_stream(stream_id);
        return;
    }
    let (reader, writer) = tokio::io::split(target);
    let activity = Arc::new(Mutex::new(Instant::now()));
    let upload = pump_relay_to_target(
        tunnel.clone(),
        stream.clone(),
        stream_id,
        inbound_rx,
        writer,
        activity.clone(),
    );
    let download = pump_target_to_relay(
        tunnel.clone(),
        stream.clone(),
        stream_id,
        reader,
        config.max_frame_bytes,
        activity.clone(),
    );
    let watchdog = watch_local_stream(stream.clone(), activity, config.idle_timeout());
    tokio::pin!(upload, download, watchdog);
    tokio::select! {
        _ = async { tokio::try_join!(upload, download) } => {}
        _ = &mut watchdog => {}
        () = stream.cancel.cancelled() => {}
    }
    stream.cancel.cancel();
    tunnel.remove_stream(stream_id);
    let _ = tunnel
        .send(Frame::code(
            FrameKind::Close,
            stream_id,
            ErrorCode::TunnelLost,
        ))
        .await;
}

async fn pump_relay_to_target(
    tunnel: Arc<NodeTunnel>,
    stream: Arc<NodeStream>,
    stream_id: u64,
    mut inbound_rx: mpsc::Receiver<NodeInbound>,
    mut writer: WriteHalf<TcpStream>,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    loop {
        let inbound = tokio::select! {
            () = stream.cancel.cancelled() => return Ok(()),
            inbound = inbound_rx.recv() => inbound.ok_or_else(|| {
                RelayError::stable(ErrorCode::TunnelLost, "relay stream channel closed")
            })?,
        };
        match inbound {
            NodeInbound::Data(bytes) => {
                writer.write_all(&bytes).await?;
                let amount = u32::try_from(bytes.len()).map_err(|_| {
                    RelayError::stable(
                        ErrorCode::FrameTooLarge,
                        "payload cannot update flow window",
                    )
                })?;
                stream
                    .receive_remaining
                    .fetch_add(u64::from(amount), Ordering::Release);
                tunnel
                    .send(Frame::u32(FrameKind::WindowUpdate, stream_id, amount))
                    .await?;
                touch_activity(&activity);
            }
            NodeInbound::Fin => {
                writer.shutdown().await?;
                return Ok(());
            }
            NodeInbound::Close => return Ok(()),
        }
    }
}

async fn pump_target_to_relay(
    tunnel: Arc<NodeTunnel>,
    stream: Arc<NodeStream>,
    stream_id: u64,
    mut reader: ReadHalf<TcpStream>,
    max_frame_bytes: usize,
    activity: Arc<Mutex<Instant>>,
) -> Result<()> {
    let mut buffer = vec![0_u8; max_frame_bytes];
    loop {
        let read = tokio::select! {
            () = stream.cancel.cancelled() => return Ok(()),
            read = reader.read(&mut buffer) => read?,
        };
        if read == 0 {
            tunnel
                .send(Frame::new(FrameKind::Fin, stream_id, Vec::new()))
                .await?;
            return Ok(());
        }
        stream.send_credit.consume(read, &stream.cancel).await?;
        tunnel
            .send(Frame::new(
                FrameKind::Data,
                stream_id,
                buffer[..read].to_vec(),
            ))
            .await?;
        touch_activity(&activity);
    }
}

async fn watch_local_stream(
    stream: Arc<NodeStream>,
    activity: Arc<Mutex<Instant>>,
    idle_timeout: Duration,
) -> Result<()> {
    loop {
        tokio::select! {
            () = stream.cancel.cancelled() => return Ok(()),
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        if activity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
            > idle_timeout
        {
            return Err(RelayError::stable(
                ErrorCode::IdleTimeout,
                "local relay stream exceeded its idle timeout",
            ));
        }
    }
}

async fn run_node_heartbeat(tunnel: Arc<NodeTunnel>, config: Arc<NodeConnectorConfig>) {
    let mut sequence = 0_u64;
    loop {
        tokio::select! {
            () = tunnel.cancel.cancelled() => return,
            () = tokio::time::sleep(config.heartbeat_interval()) => {}
        }
        if tunnel
            .last_pong
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
            > config.heartbeat_timeout()
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

fn debit_window(stream: &NodeStream, bytes: usize) -> Result<()> {
    let bytes = u64::try_from(bytes).map_err(|_| {
        RelayError::stable(ErrorCode::ProtocolInvalid, "payload length is unsupported")
    })?;
    stream
        .receive_remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(bytes)
        })
        .map(|_| ())
        .map_err(|_| {
            RelayError::stable(
                ErrorCode::ProtocolInvalid,
                "relay exceeded the stream receive window",
            )
        })
}

fn touch_activity(activity: &Mutex<Instant>) {
    *activity
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
}

fn build_client_config(config: &NodeConnectorConfig) -> Result<Arc<ClientConfig>> {
    ensure_crypto_provider()?;
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&config.relay_ca_path)? {
        roots
            .add(certificate)
            .map_err(|error| RelayError::Tls(format!("invalid relay CA: {error}")))?;
    }
    let certificates = load_certificates(&config.tls_cert_path)?;
    let private_key = load_private_key(&config.tls_key_path)?;
    let mut client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, private_key)
        .map_err(|error| RelayError::Tls(format!("invalid node identity: {error}")))?;
    client.alpn_protocols = vec![b"pn-relay-v1".to_vec()];
    Ok(Arc::new(client))
}

fn trim_one_line_ending(mut value: Vec<u8>) -> Vec<u8> {
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    value
}

#[derive(Debug)]
struct Backoff {
    initial: Duration,
    maximum: Duration,
    next: Duration,
}

impl Backoff {
    fn new(initial: Duration, maximum: Duration) -> Self {
        Self {
            initial,
            maximum,
            next: initial,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let current = self.next;
        self.next = self.next.saturating_mul(2).min(self.maximum);
        current
    }

    fn reset(&mut self) {
        self.next = self.initial;
    }
}

const fn default_max_frame_bytes() -> usize {
    65_536
}
const fn default_command_queue_frames() -> usize {
    256
}
const fn default_stream_buffer_frames() -> usize {
    16
}
const fn default_initial_window_bytes() -> u32 {
    262_144
}
const fn default_max_streams() -> usize {
    16
}
const fn default_connect_timeout_secs() -> u64 {
    10
}
const fn default_idle_timeout_secs() -> u64 {
    1_800
}
const fn default_heartbeat_interval_secs() -> u64 {
    15
}
const fn default_heartbeat_timeout_secs() -> u64 {
    45
}
const fn default_reconnect_initial_ms() -> u64 {
    500
}
const fn default_reconnect_max_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_capped_and_resettable() {
        let mut backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(25));
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.next_delay(), Duration::from_millis(25));
        assert_eq!(backoff.next_delay(), Duration::from_millis(25));
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
    }

    #[test]
    fn rejects_non_loopback_target() {
        let mut config = test_config();
        config.local_target = "192.0.2.10:443".parse().unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn example_node_configuration_stays_valid() {
        let config: NodeConnectorConfig =
            toml::from_str(include_str!("../node.example.toml")).unwrap();
        config.validate().unwrap();
    }

    fn test_config() -> NodeConnectorConfig {
        NodeConnectorConfig {
            relay_address: "127.0.0.1:7443".parse().unwrap(),
            relay_server_name: "localhost".to_owned(),
            route_id: "route_0123456789abcdef".to_owned(),
            route_token_path: "token".into(),
            tls_cert_path: "node.pem".into(),
            tls_key_path: "node-key.pem".into(),
            relay_ca_path: "ca.pem".into(),
            local_target: "127.0.0.1:443".parse().unwrap(),
            max_frame_bytes: 1_024,
            command_queue_frames: 4,
            stream_buffer_frames: 2,
            initial_window_bytes: 1_024,
            max_streams: 1,
            connect_timeout_secs: 1,
            idle_timeout_secs: 2,
            heartbeat_interval_secs: 1,
            heartbeat_timeout_secs: 2,
            reconnect_initial_ms: 10,
            reconnect_max_secs: 1,
        }
    }
}
