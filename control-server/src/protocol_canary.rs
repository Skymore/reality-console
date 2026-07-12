use crate::db::{Database, DatabaseError};
use async_trait::async_trait;
use control_protocol::id::{EndpointId, NetworkId, NodeId, Revision};
use control_protocol::secret::Secret;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(30);
const DEFAULT_SUCCESS_INTERVAL: Duration = Duration::from_secs(10 * 60);
const DEFAULT_FAILURE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_NODE_ONLINE_WINDOW: Duration = Duration::from_secs(90);
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// Verified local Xray executable used only as an external canary client.
#[derive(Clone)]
pub struct ProtocolCanaryConfig {
    binary_path: PathBuf,
    expected_sha256: String,
}

impl ProtocolCanaryConfig {
    /// Validates an explicit absolute executable path and lowercase SHA-256.
    ///
    /// # Errors
    ///
    /// Returns an error for a relative path or malformed digest.
    pub fn new(binary_path: PathBuf, expected_sha256: String) -> Result<Self, CanaryConfigError> {
        if !binary_path.is_absolute() {
            return Err(CanaryConfigError::InvalidBinaryPath);
        }
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CanaryConfigError::InvalidDigest);
        }
        Ok(Self {
            binary_path,
            expected_sha256,
        })
    }
}

impl fmt::Debug for ProtocolCanaryConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolCanaryConfig")
            .field("binary_path", &self.binary_path)
            .field("expected_sha256", &self.expected_sha256)
            .finish()
    }
}

/// Timing policy for the bounded protocol-aware worker.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolCanaryLoopOptions {
    pub poll_interval: Duration,
    pub connect_timeout: Duration,
    pub claim_lease: Duration,
    pub success_interval: Duration,
    pub failure_interval: Duration,
    pub node_online_window: Duration,
}

impl Default for ProtocolCanaryLoopOptions {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            claim_lease: DEFAULT_CLAIM_LEASE,
            success_interval: DEFAULT_SUCCESS_INTERVAL,
            failure_interval: DEFAULT_FAILURE_INTERVAL,
            node_online_window: DEFAULT_NODE_ONLINE_WINDOW,
        }
    }
}

impl ProtocolCanaryLoopOptions {
    pub(crate) fn validate(self) -> Result<(), CanaryServiceError> {
        if self.poll_interval.is_zero()
            || self.connect_timeout.is_zero()
            || self.claim_lease <= self.connect_timeout
            || self.success_interval.is_zero()
            || self.failure_interval.is_zero()
            || self.node_online_window.is_zero()
        {
            return Err(CanaryServiceError::InvalidOptions);
        }
        Ok(())
    }
}

/// One finite claim containing the minimum secret material needed by Xray.
pub struct ProtocolCanaryJob {
    pub(crate) probe_id: Uuid,
    pub(crate) runner_id: Uuid,
    pub(crate) network_id: NetworkId,
    pub(crate) node_id: NodeId,
    pub(crate) endpoint_id: EndpointId,
    pub(crate) address: String,
    pub(crate) resolved_address: IpAddr,
    pub(crate) port: u16,
    pub(crate) applied_revision: Revision,
    pub(crate) candidate_generation: i64,
    pub(crate) claim_expires_at: i64,
    pub(crate) claim_token: Secret<[u8; 32]>,
    pub(crate) vless_uuid: Secret<String>,
    pub(crate) server_name: String,
    pub(crate) reality_public_key: String,
    pub(crate) reality_short_id: String,
}

impl fmt::Debug for ProtocolCanaryJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolCanaryJob")
            .field("probe_id", &self.probe_id)
            .field("node_id", &self.node_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("address", &self.address)
            .field("resolved_address", &self.resolved_address)
            .field("port", &self.port)
            .field("applied_revision", &self.applied_revision)
            .field("vless_uuid", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Closed, secret-free outcome of a real VLESS+REALITY data-plane attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolCanaryResult {
    Connected { latency: Duration },
    Failed { code: ProtocolCanaryErrorCode },
}

/// Stable failure reason without child output or endpoint secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolCanaryErrorCode {
    BinaryInvalid,
    ClientStartFailed,
    ClientUnhealthy,
    VlessRealityHandshakeFailed,
    TimedOut,
}

impl ProtocolCanaryErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BinaryInvalid => "protocol_binary_invalid",
            Self::ClientStartFailed => "protocol_client_start_failed",
            Self::ClientUnhealthy => "protocol_client_unhealthy",
            Self::VlessRealityHandshakeFailed => "protocol_vless_reality_failed",
            Self::TimedOut => "protocol_timeout",
        }
    }
}

#[async_trait]
pub trait ProtocolCanaryExecutor: Send + Sync {
    async fn execute(
        &self,
        job: &ProtocolCanaryJob,
        timeout_duration: Duration,
    ) -> ProtocolCanaryResult;
}

/// Executes a secret-file-only Xray client and a SOCKS connect through it.
#[derive(Debug, Clone)]
pub struct XrayProtocolCanaryExecutor {
    config: ProtocolCanaryConfig,
}

impl XrayProtocolCanaryExecutor {
    #[must_use]
    pub const fn new(config: ProtocolCanaryConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ProtocolCanaryExecutor for XrayProtocolCanaryExecutor {
    async fn execute(
        &self,
        job: &ProtocolCanaryJob,
        timeout_duration: Duration,
    ) -> ProtocolCanaryResult {
        match timeout(timeout_duration, execute_xray_canary(&self.config, job)).await {
            Ok(Ok(latency)) => ProtocolCanaryResult::Connected { latency },
            Ok(Err(code)) => ProtocolCanaryResult::Failed { code },
            Err(_) => ProtocolCanaryResult::Failed {
                code: ProtocolCanaryErrorCode::TimedOut,
            },
        }
    }
}

/// Runs canary claims until shutdown without holding the database during I/O.
///
/// # Errors
///
/// Returns an error for invalid timing options or a durable claim failure.
pub async fn run_protocol_canary_until<E, S>(
    database: Database,
    executor: E,
    options: ProtocolCanaryLoopOptions,
    shutdown: S,
) -> Result<(), CanaryServiceError>
where
    E: ProtocolCanaryExecutor,
    S: std::future::Future<Output = ()>,
{
    options.validate()?;
    let runner_id = Uuid::new_v4();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            () = tokio::task::yield_now() => {}
        }
        let processed = run_once(&database, runner_id, &executor, options).await?;
        if !processed {
            tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                () = sleep(options.poll_interval) => {}
            }
        }
    }
}

async fn run_once<E: ProtocolCanaryExecutor>(
    database: &Database,
    runner_id: Uuid,
    executor: &E,
    options: ProtocolCanaryLoopOptions,
) -> Result<bool, CanaryServiceError> {
    let Some(job) = database.claim_protocol_canary(runner_id, options).await? else {
        return Ok(false);
    };
    let result = executor.execute(&job, options.connect_timeout).await;
    database.complete_protocol_canary(job, result).await?;
    Ok(true)
}

async fn execute_xray_canary(
    config: &ProtocolCanaryConfig,
    job: &ProtocolCanaryJob,
) -> Result<Duration, ProtocolCanaryErrorCode> {
    verify_binary(config)
        .await
        .map_err(|_| ProtocolCanaryErrorCode::BinaryInvalid)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    let local_port = listener
        .local_addr()
        .map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?
        .port();
    drop(listener);
    let mut config_file =
        NamedTempFile::new().map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    set_owner_only(config_file.path()).map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    let client_config = xray_client_config(job, local_port);
    serde_json::to_writer(config_file.as_file_mut(), &client_config)
        .map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    config_file
        .as_file_mut()
        .sync_all()
        .map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    let mut child = Command::new(&config.binary_path)
        .arg("run")
        .arg("-config")
        .arg(config_file.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| ProtocolCanaryErrorCode::ClientStartFailed)?;
    wait_for_listener(local_port, &mut child).await?;
    let started = Instant::now();
    let result = socks_connect(local_port, &job.server_name, 443).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    result.map(|()| started.elapsed())
}

fn xray_client_config(job: &ProtocolCanaryJob, local_port: u16) -> serde_json::Value {
    json!({
        "log": { "loglevel": "none" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{
                "address": job.resolved_address.to_string(),
                "port": job.port,
                "users": [{
                    "id": job.vless_uuid.expose_secret(),
                    "encryption": "none",
                    "flow": "xtls-rprx-vision"
                }]
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": job.server_name,
                    "fingerprint": "chrome",
                    "publicKey": job.reality_public_key,
                    "shortId": job.reality_short_id,
                    "spiderX": ""
                }
            }
        }]
    })
}

async fn verify_binary(config: &ProtocolCanaryConfig) -> Result<(), std::io::Error> {
    let path = config.binary_path.clone();
    let expected = config.expected_sha256.clone();
    tokio::task::spawn_blocking(move || {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_BINARY_BYTES
        {
            return Err(std::io::Error::other("unsafe canary binary"));
        }
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if format!("{:x}", hasher.finalize()) != expected {
            return Err(std::io::Error::other("canary binary digest mismatch"));
        }
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

async fn wait_for_listener(
    port: u16,
    child: &mut tokio::process::Child,
) -> Result<(), ProtocolCanaryErrorCode> {
    for _ in 0..50 {
        if child
            .try_wait()
            .map_err(|_| ProtocolCanaryErrorCode::ClientUnhealthy)?
            .is_some()
        {
            return Err(ProtocolCanaryErrorCode::ClientUnhealthy);
        }
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(ProtocolCanaryErrorCode::ClientUnhealthy)
}

async fn socks_connect(
    local_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<(), ProtocolCanaryErrorCode> {
    let host = target_host.as_bytes();
    let host_len = u8::try_from(host.len())
        .map_err(|_| ProtocolCanaryErrorCode::VlessRealityHandshakeFailed)?;
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, local_port))
        .await
        .map_err(|_| ProtocolCanaryErrorCode::ClientUnhealthy)?;
    stream
        .write_all(&[5, 1, 0])
        .await
        .map_err(|_| ProtocolCanaryErrorCode::ClientUnhealthy)?;
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|_| ProtocolCanaryErrorCode::ClientUnhealthy)?;
    if greeting != [5, 0] {
        return Err(ProtocolCanaryErrorCode::ClientUnhealthy);
    }
    let mut request = Vec::with_capacity(host.len() + 7);
    request.extend_from_slice(&[5, 1, 0, 3, host_len]);
    request.extend_from_slice(host);
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|_| ProtocolCanaryErrorCode::VlessRealityHandshakeFailed)?;
    let mut response = [0_u8; 4];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| ProtocolCanaryErrorCode::VlessRealityHandshakeFailed)?;
    if response[0] != 5 || response[1] != 0 {
        return Err(ProtocolCanaryErrorCode::VlessRealityHandshakeFailed);
    }
    drain_socks_address(&mut stream, response[3]).await
}

async fn drain_socks_address(
    stream: &mut TcpStream,
    address_type: u8,
) -> Result<(), ProtocolCanaryErrorCode> {
    let address_length = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|_| ProtocolCanaryErrorCode::VlessRealityHandshakeFailed)?;
            usize::from(length[0])
        }
        _ => return Err(ProtocolCanaryErrorCode::VlessRealityHandshakeFailed),
    };
    let mut remainder = vec![0_u8; address_length + 2];
    stream
        .read_exact(&mut remainder)
        .await
        .map_err(|_| ProtocolCanaryErrorCode::VlessRealityHandshakeFailed)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CanaryConfigError {
    #[error("protocol canary Xray path must be absolute")]
    InvalidBinaryPath,
    #[error("protocol canary Xray SHA-256 must be 64 lowercase hexadecimal characters")]
    InvalidDigest,
}

#[derive(Debug, Error)]
pub enum CanaryServiceError {
    #[error("protocol canary loop timing options are invalid")]
    InvalidOptions,
    #[error(transparent)]
    Database(#[from] DatabaseError),
}

#[cfg(test)]
mod tests {
    use super::{socks_connect, ProtocolCanaryErrorCode};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks_success_requires_a_complete_connect_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            let mut rest = vec![0_u8; usize::from(request[4]) + 2];
            stream.read_exact(&mut rest).await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
        });
        socks_connect(port, "example.com", 443).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks_failure_is_protocol_failure_not_tcp_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            let mut rest = vec![0_u8; usize::from(request[4]) + 2];
            stream.read_exact(&mut rest).await.unwrap();
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        assert_eq!(
            socks_connect(port, "example.com", 443).await.unwrap_err(),
            ProtocolCanaryErrorCode::VlessRealityHandshakeFailed
        );
    }
}
