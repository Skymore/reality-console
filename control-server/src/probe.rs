use crate::db::{Database, DatabaseError};
use async_trait::async_trait;
use control_protocol::id::{EndpointId, NetworkId, NodeId, RequestId, Revision};
use control_protocol::probe::{
    is_public_probe_ipv4, TcpProbeExecutorRequest, TcpProbeExecutorResponse,
    TcpProbeExecutorResult, MAX_TCP_PROBE_TARGETS, MAX_TCP_PROBE_TIMEOUT_MILLIS,
    MIN_TCP_PROBE_TIMEOUT_MILLIS, TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
};
use control_protocol::secret::Secret;
use futures_util::StreamExt as _;
use reqwest::redirect::Policy;
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Instant};
use url::{Host, Url};
use uuid::Uuid;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(30);
const DEFAULT_SUCCESS_INTERVAL: Duration = Duration::from_secs(15 * 60);
const DEFAULT_FAILURE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_NODE_ONLINE_WINDOW: Duration = Duration::from_secs(90);
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_REMOTE_RESPONSE_BYTES: usize = 8 * 1024;
const REMOTE_HTTP_OVERHEAD: Duration = Duration::from_secs(5);
const REMOTE_PROBE_PATH: &str = "/v1/tcp-probe";
const MIN_REMOTE_TOKEN_BYTES: usize = 32;
const MAX_REMOTE_TOKEN_BYTES: usize = 4 * 1024;

/// Selects whether this process executes endpoint probes itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// Store candidates without executing probes in the controller process.
    Disabled,
    /// Execute TCP preflight from this process. This is valid only when the
    /// controller is outside the candidate node's LAN.
    LocalTcp,
    /// Resolve and pin targets locally, then invoke an external HTTPS executor.
    RemoteHttp,
}

impl FromStr for ProbeMode {
    type Err = ProbeModeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "local-tcp" => Ok(Self::LocalTcp),
            "remote-http" => Ok(Self::RemoteHttp),
            _ => Err(ProbeModeParseError),
        }
    }
}

/// Invalid `CONTROL_PROBE_MODE` value.
#[derive(Debug, Error)]
#[error("invalid probe mode")]
pub struct ProbeModeParseError;

/// Validated endpoint and redacted deployment credential for a remote executor.
#[derive(Clone)]
pub struct RemoteTcpProbeConfig {
    endpoint: Url,
    token: Secret<String>,
    allow_loopback_http: bool,
}

impl RemoteTcpProbeConfig {
    /// Builds production remote-executor configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTcpProbeConfigError`] unless the URL is an exact HTTPS
    /// executor endpoint and the deployment token is a bounded visible-ASCII
    /// Bearer value without comma separators.
    pub fn new(endpoint: &str, token: String) -> Result<Self, RemoteTcpProbeConfigError> {
        Self::build(endpoint, token, false)
    }

    fn build(
        endpoint: &str,
        token: String,
        allow_loopback_http: bool,
    ) -> Result<Self, RemoteTcpProbeConfigError> {
        let endpoint = Url::parse(endpoint).map_err(|_| RemoteTcpProbeConfigError::InvalidUrl)?;
        validate_remote_endpoint(&endpoint, allow_loopback_http)?;
        let token_is_valid = (MIN_REMOTE_TOKEN_BYTES..=MAX_REMOTE_TOKEN_BYTES)
            .contains(&token.len())
            && token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b',');
        if !token_is_valid {
            return Err(RemoteTcpProbeConfigError::InvalidToken);
        }
        Ok(Self {
            endpoint,
            token: Secret::new(token),
            allow_loopback_http,
        })
    }

    #[cfg(test)]
    fn for_test(endpoint: &str, token: &str) -> Self {
        Self::build(endpoint, token.to_string(), true).expect("valid test remote probe config")
    }
}

impl fmt::Debug for RemoteTcpProbeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteTcpProbeConfig")
            .field("endpoint", &self.endpoint)
            .field("token", &"[redacted]")
            .field("allow_loopback_http", &self.allow_loopback_http)
            .finish()
    }
}

/// Invalid remote TCP executor deployment configuration.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTcpProbeConfigError {
    #[error("remote TCP probe URL must be the exact HTTPS /v1/tcp-probe endpoint")]
    InvalidUrl,
    #[error("remote TCP probe token must contain 32 to 4096 visible ASCII bytes without commas")]
    InvalidToken,
}

/// Timing policy for one resilient TCP preflight worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpProbeLoopOptions {
    pub poll_interval: Duration,
    pub connect_timeout: Duration,
    pub claim_lease: Duration,
    pub success_interval: Duration,
    pub failure_interval: Duration,
    pub node_online_window: Duration,
}

impl Default for TcpProbeLoopOptions {
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

impl TcpProbeLoopOptions {
    fn validate(self) -> Result<Self, ProbeServiceError> {
        let valid = !self.poll_interval.is_zero()
            && !self.connect_timeout.is_zero()
            && !self.claim_lease.is_zero()
            && !self.success_interval.is_zero()
            && !self.failure_interval.is_zero()
            && !self.node_online_window.is_zero()
            && self.poll_interval <= Duration::from_secs(60)
            && self.connect_timeout <= Duration::from_secs(30)
            && self.claim_lease <= Duration::from_secs(5 * 60)
            && self.success_interval <= Duration::from_secs(60 * 60)
            && self.failure_interval <= Duration::from_secs(15 * 60)
            && self.node_online_window <= Duration::from_secs(10 * 60)
            && self.claim_lease > self.connect_timeout;
        valid
            .then_some(self)
            .ok_or(ProbeServiceError::InvalidOptions)
    }

    pub(crate) fn validated_schedule(self) -> Result<ProbeSchedule, ProbeServiceError> {
        let validated = self.validate()?;
        Ok(ProbeSchedule {
            claim_lease: validated.claim_lease,
            success_interval: validated.success_interval,
            failure_interval: validated.failure_interval,
            node_online_window: validated.node_online_window,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProbeSchedule {
    pub claim_lease: Duration,
    pub success_interval: Duration,
    pub failure_interval: Duration,
    pub node_online_window: Duration,
}

/// One durably claimed TCP preflight. The claim token is always redacted.
#[derive(Clone)]
pub struct TcpProbeJob {
    pub(crate) probe_id: Uuid,
    pub(crate) runner_id: Uuid,
    pub(crate) network_id: NetworkId,
    pub(crate) node_id: NodeId,
    pub(crate) endpoint_id: EndpointId,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) applied_revision: Revision,
    pub(crate) candidate_generation: i64,
    pub(crate) claim_expires_at: i64,
    pub(crate) claim_token: Secret<[u8; 32]>,
}

impl TcpProbeJob {
    #[must_use]
    pub const fn probe_id(&self) -> Uuid {
        self.probe_id
    }

    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Stable failure code produced by the TCP preflight boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpProbeErrorCode {
    TargetNotPublic,
    NoSupportedAddress,
    DnsFailed,
    DnsTimeout,
    TooManyAddresses,
    TcpUnreachable,
    TcpTimeout,
    ExecutorFailed,
}

impl TcpProbeErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetNotPublic => "direct_target_not_public",
            Self::NoSupportedAddress => "direct_no_supported_address",
            Self::DnsFailed => "direct_dns_failed",
            Self::DnsTimeout => "direct_dns_timeout",
            Self::TooManyAddresses => "direct_dns_too_many_addresses",
            Self::TcpUnreachable => "direct_tcp_unreachable",
            Self::TcpTimeout => "direct_tcp_timeout",
            Self::ExecutorFailed => "direct_probe_executor_failed",
        }
    }
}

/// Secret-free result returned by a TCP preflight executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpProbeResult {
    Connected {
        resolved_address: IpAddr,
        latency: Duration,
    },
    Failed {
        code: TcpProbeErrorCode,
        resolved_address: Option<IpAddr>,
        latency: Option<Duration>,
    },
}

impl TcpProbeResult {
    #[must_use]
    pub const fn connected(resolved_address: IpAddr, latency: Duration) -> Self {
        Self::Connected {
            resolved_address,
            latency,
        }
    }

    #[must_use]
    pub const fn failed(code: TcpProbeErrorCode) -> Self {
        Self::Failed {
            code,
            resolved_address: None,
            latency: None,
        }
    }
}

/// Durable completion disposition for a claimed probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpProbeCompletion {
    Recorded,
    AlreadyRecorded,
    CandidateChanged,
    ClaimExpired,
}

#[async_trait]
pub trait TcpProbeExecutor: Send + Sync {
    async fn probe(&self, address: &str, port: u16, timeout: Duration) -> TcpProbeResult;
}

/// DNS-pinned, public-address-only TCP preflight executor.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTcpProbeExecutor;

#[async_trait]
impl TcpProbeExecutor for SystemTcpProbeExecutor {
    async fn probe(&self, address: &str, port: u16, timeout: Duration) -> TcpProbeResult {
        probe_public_tcp(address, port, timeout).await
    }
}

/// HTTPS client for a privacy-minimized external TCP executor.
#[derive(Clone)]
pub struct RemoteHttpTcpProbeExecutor {
    client: reqwest::Client,
    config: RemoteTcpProbeConfig,
}

impl RemoteHttpTcpProbeExecutor {
    /// Creates a redirect-free bounded HTTPS executor client.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeServiceError::RemoteClientBuild`] when the TLS HTTP
    /// client cannot be initialized.
    pub fn new(config: RemoteTcpProbeConfig) -> Result<Self, ProbeServiceError> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(REMOTE_HTTP_OVERHEAD)
            .https_only(!config.allow_loopback_http)
            .user_agent("private-network-control/0.1 tcp-preflight")
            .build()
            .map_err(|_| ProbeServiceError::RemoteClientBuild)?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl TcpProbeExecutor for RemoteHttpTcpProbeExecutor {
    async fn probe(&self, address: &str, port: u16, timeout: Duration) -> TcpProbeResult {
        probe_remote_http(self, address, port, timeout).await
    }
}

/// Runs the local TCP preflight worker until the supplied shutdown future resolves.
///
/// Database and network failures are isolated to one cycle and retried. A TCP
/// success is only preflight evidence and never marks an endpoint `verified`.
///
/// # Errors
///
/// Returns [`ProbeServiceError::InvalidOptions`] before claiming work when the
/// supplied timing policy is unsafe or internally inconsistent.
pub async fn run_local_tcp_until<F>(
    database: Database,
    options: TcpProbeLoopOptions,
    shutdown: F,
) -> Result<(), ProbeServiceError>
where
    F: Future<Output = ()>,
{
    let options = options.validate()?;
    run_tcp_until(database, options, SystemTcpProbeExecutor, shutdown).await
}

/// Runs privacy-minimized TCP preflight through an external HTTP executor.
///
/// # Errors
///
/// Returns [`ProbeServiceError`] before claiming work when options cannot fit
/// inside the durable claim lease or the bounded HTTPS client cannot be built.
pub async fn run_remote_tcp_until<F>(
    database: Database,
    options: TcpProbeLoopOptions,
    config: RemoteTcpProbeConfig,
    shutdown: F,
) -> Result<(), ProbeServiceError>
where
    F: Future<Output = ()>,
{
    let options = options.validate()?;
    let maximum_cycle = options
        .connect_timeout
        .saturating_mul(2)
        .saturating_add(REMOTE_HTTP_OVERHEAD);
    if options.connect_timeout.as_millis() > u128::from(MAX_TCP_PROBE_TIMEOUT_MILLIS)
        || options.connect_timeout.as_millis() < u128::from(MIN_TCP_PROBE_TIMEOUT_MILLIS)
        || options.claim_lease <= maximum_cycle
    {
        return Err(ProbeServiceError::InvalidOptions);
    }
    let executor = RemoteHttpTcpProbeExecutor::new(config)?;
    run_tcp_until(database, options, executor, shutdown).await
}

async fn run_tcp_until<E, F>(
    database: Database,
    options: TcpProbeLoopOptions,
    executor: E,
    shutdown: F,
) -> Result<(), ProbeServiceError>
where
    E: TcpProbeExecutor,
    F: Future<Output = ()>,
{
    let runner_id = Uuid::new_v4();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            () = tokio::task::yield_now() => {}
        }

        let processed = match run_tcp_probe_once(&database, runner_id, &executor, options).await {
            Ok(processed) => processed,
            Err(error) => {
                tracing::warn!(error = %error, "TCP endpoint probe cycle failed; retrying");
                false
            }
        };
        if processed {
            continue;
        }
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            () = tokio::time::sleep(options.poll_interval) => {}
        }
    }
}

async fn run_tcp_probe_once<E>(
    database: &Database,
    runner_id: Uuid,
    executor: &E,
    options: TcpProbeLoopOptions,
) -> Result<bool, DatabaseError>
where
    E: TcpProbeExecutor,
{
    let Some(job) = database.claim_tcp_probe(runner_id, options).await? else {
        return Ok(false);
    };
    let probe_id = job.probe_id;
    let node_id = job.node_id;
    let endpoint_id = job.endpoint_id;
    let result = executor
        .probe(&job.address, job.port, options.connect_timeout)
        .await;
    let completion = database.complete_tcp_probe(job, result).await?;
    tracing::info!(
        %probe_id,
        %node_id,
        %endpoint_id,
        ?completion,
        "TCP endpoint preflight completed"
    );
    Ok(true)
}

async fn probe_remote_http(
    executor: &RemoteHttpTcpProbeExecutor,
    address: &str,
    port: u16,
    timeout: Duration,
) -> TcpProbeResult {
    if port == 0
        || timeout.as_millis() < u128::from(MIN_TCP_PROBE_TIMEOUT_MILLIS)
        || timeout.as_millis() > u128::from(MAX_TCP_PROBE_TIMEOUT_MILLIS)
    {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    }
    let started = Instant::now();
    let Some(dns_deadline) = started.checked_add(timeout) else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    let resolved = match resolve_public_targets(address, port, dns_deadline).await {
        Ok(resolved) => resolved,
        Err(code) => return TcpProbeResult::failed(code),
    };
    let targets = resolved
        .into_iter()
        .filter_map(|target| match target.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .take(MAX_TCP_PROBE_TARGETS)
        .collect::<Vec<_>>();
    let Some(fallback_address) = targets.first().copied() else {
        return TcpProbeResult::failed(TcpProbeErrorCode::NoSupportedAddress);
    };
    let Ok(timeout_millis) = u32::try_from(timeout.as_millis()) else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    let request = TcpProbeExecutorRequest {
        schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
        request_id: RequestId::new(),
        targets,
        port,
        timeout_millis,
    };
    if request.validate().is_err() {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    }

    let http_timeout = timeout.saturating_add(REMOTE_HTTP_OVERHEAD);
    let Ok(response) = executor
        .client
        .post(executor.config.endpoint.clone())
        .timeout(http_timeout)
        .bearer_auth(executor.config.token.expose_secret())
        .json(&request)
        .send()
        .await
    else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    if response.status() != reqwest::StatusCode::OK || !response_is_json(&response) {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    }
    let Some(body) = read_bounded_response(response, MAX_REMOTE_RESPONSE_BYTES).await else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    let Ok(response) = serde_json::from_slice::<TcpProbeExecutorResponse>(&body) else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    if response.validate_for(&request).is_err() {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    }

    match response.result {
        TcpProbeExecutorResult::Connected {
            resolved_address,
            latency_millis,
        } => TcpProbeResult::Connected {
            resolved_address: IpAddr::V4(resolved_address),
            latency: Duration::from_millis(u64::from(latency_millis)),
        },
        TcpProbeExecutorResult::Unreachable { latency_millis } => TcpProbeResult::Failed {
            code: TcpProbeErrorCode::TcpUnreachable,
            resolved_address: Some(IpAddr::V4(fallback_address)),
            latency: Some(Duration::from_millis(u64::from(latency_millis))),
        },
        TcpProbeExecutorResult::TimedOut { latency_millis } => TcpProbeResult::Failed {
            code: TcpProbeErrorCode::TcpTimeout,
            resolved_address: Some(IpAddr::V4(fallback_address)),
            latency: Some(Duration::from_millis(u64::from(latency_millis))),
        },
        TcpProbeExecutorResult::ExecutorFailed => {
            TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed)
        }
    }
}

fn response_is_json(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        })
}

async fn read_bounded_response(response: reqwest::Response, maximum: usize) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        let next_length = body.len().checked_add(chunk.len())?;
        if next_length > maximum {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

async fn probe_public_tcp(address: &str, port: u16, timeout: Duration) -> TcpProbeResult {
    if port == 0 || timeout.is_zero() {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    }
    let started = Instant::now();
    let Some(deadline) = started.checked_add(timeout) else {
        return TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed);
    };
    let targets = match resolve_public_targets(address, port, deadline).await {
        Ok(targets) => targets,
        Err(code) => return TcpProbeResult::failed(code),
    };
    let fallback_address = targets.first().map(SocketAddr::ip);
    let mut attempts = JoinSet::new();
    for target in targets {
        attempts.spawn(async move { (target, TcpStream::connect(target).await) });
    }
    loop {
        match timeout_at(deadline, attempts.join_next()).await {
            Ok(Some(Ok((target, Ok(stream))))) => {
                drop(stream);
                return TcpProbeResult::Connected {
                    resolved_address: target.ip(),
                    latency: started.elapsed(),
                };
            }
            Ok(Some(Ok((_, Err(_))) | Err(_))) => {}
            Ok(None) => {
                return TcpProbeResult::Failed {
                    code: TcpProbeErrorCode::TcpUnreachable,
                    resolved_address: fallback_address,
                    latency: Some(started.elapsed()),
                };
            }
            Err(_) => {
                return TcpProbeResult::Failed {
                    code: TcpProbeErrorCode::TcpTimeout,
                    resolved_address: fallback_address,
                    latency: Some(started.elapsed()),
                };
            }
        }
    }
}

async fn resolve_public_targets(
    address: &str,
    port: u16,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, TcpProbeErrorCode> {
    if let Ok(address) = address.parse::<IpAddr>() {
        return is_publishable_address(address)
            .then_some(vec![SocketAddr::new(address, port)])
            .ok_or(TcpProbeErrorCode::TargetNotPublic);
    }
    let resolved = timeout_at(deadline, lookup_host((address, port)))
        .await
        .map_err(|_| TcpProbeErrorCode::DnsTimeout)?
        .map_err(|_| TcpProbeErrorCode::DnsFailed)?;
    let mut targets = BTreeSet::new();
    for target in resolved {
        if !is_publishable_address(target.ip()) {
            return Err(TcpProbeErrorCode::TargetNotPublic);
        }
        targets.insert(target);
        if targets.len() > MAX_RESOLVED_ADDRESSES {
            return Err(TcpProbeErrorCode::TooManyAddresses);
        }
    }
    (!targets.is_empty())
        .then(|| targets.into_iter().collect())
        .ok_or(TcpProbeErrorCode::DnsFailed)
}

fn is_publishable_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_publishable_ipv4(address),
        IpAddr::V6(address) => is_publishable_ipv6(address),
    }
}

fn is_publishable_ipv4(address: Ipv4Addr) -> bool {
    is_public_probe_ipv4(address)
}

fn is_publishable_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_publishable_ipv4(mapped);
    }
    let segments = address.segments();
    (segments[0] & 0xe000) == 0x2000
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
        && !(segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020))
}

fn validate_remote_endpoint(
    endpoint: &Url,
    allow_loopback_http: bool,
) -> Result<(), RemoteTcpProbeConfigError> {
    let Some(host) = endpoint.host() else {
        return Err(RemoteTcpProbeConfigError::InvalidUrl);
    };
    let loopback = match host {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(domain) => domain == "localhost" || domain.ends_with(".localhost"),
    };
    let host_is_allowed = match host {
        Host::Ipv4(address) => is_public_probe_ipv4(address) || (allow_loopback_http && loopback),
        Host::Ipv6(address) => is_publishable_ipv6(address) || (allow_loopback_http && loopback),
        Host::Domain(_) => !loopback || allow_loopback_http,
    };
    let transport_is_allowed = endpoint.scheme() == "https"
        || (allow_loopback_http && loopback && endpoint.scheme() == "http");
    if !transport_is_allowed
        || !host_is_allowed
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.path() != REMOTE_PROBE_PATH
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(RemoteTcpProbeConfigError::InvalidUrl);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeServiceError {
    #[error("TCP probe loop timing options are invalid")]
    InvalidOptions,
    #[error("remote TCP probe HTTP client could not be initialized")]
    RemoteClientBuild,
}

#[cfg(test)]
mod tests {
    use super::{
        is_publishable_address, ProbeMode, RemoteHttpTcpProbeExecutor, RemoteTcpProbeConfig,
        SystemTcpProbeExecutor, TcpProbeErrorCode, TcpProbeExecutor, TcpProbeLoopOptions,
        TcpProbeResult,
    };
    use axum::http::{header, HeaderMap, StatusCode};
    use axum::response::Redirect;
    use axum::routing::post;
    use axum::{Json, Router};
    use control_protocol::probe::{
        TcpProbeExecutorRequest, TcpProbeExecutorResponse, TcpProbeExecutorResult,
        TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr as _;
    use std::time::Duration;
    use tokio::net::TcpListener;

    const REMOTE_TOKEN: &str = "remote-probe-test-token-with-at-least-32-bytes";

    #[test]
    fn mode_is_explicit_and_closed() {
        assert_eq!(
            ProbeMode::from_str("disabled").unwrap(),
            ProbeMode::Disabled
        );
        assert_eq!(
            ProbeMode::from_str("local-tcp").unwrap(),
            ProbeMode::LocalTcp
        );
        assert_eq!(
            ProbeMode::from_str("remote-http").unwrap(),
            ProbeMode::RemoteHttp
        );
        assert!(ProbeMode::from_str("tcp").is_err());
    }

    #[test]
    fn remote_configuration_is_strict_and_redacts_its_token() {
        let config = RemoteTcpProbeConfig::new(
            "https://probe.example/v1/tcp-probe",
            REMOTE_TOKEN.to_string(),
        )
        .unwrap();
        let rendered = format!("{config:?}");
        assert!(rendered.contains("probe.example"));
        assert!(!rendered.contains(REMOTE_TOKEN));
        assert!(RemoteTcpProbeConfig::new(
            "http://probe.example/v1/tcp-probe",
            REMOTE_TOKEN.to_string()
        )
        .is_err());
        assert!(RemoteTcpProbeConfig::new(
            "https://127.0.0.1/v1/tcp-probe",
            REMOTE_TOKEN.to_string()
        )
        .is_err());
        assert!(
            RemoteTcpProbeConfig::new("https://probe.example/wrong", REMOTE_TOKEN.to_string())
                .is_err()
        );
        assert!(RemoteTcpProbeConfig::new(
            "https://probe.example/v1/tcp-probe?target=8.8.8.8",
            REMOTE_TOKEN.to_string()
        )
        .is_err());
        assert!(RemoteTcpProbeConfig::new(
            "https://probe.example/v1/tcp-probe",
            "short".to_string()
        )
        .is_err());
    }

    #[test]
    fn options_require_a_claim_longer_than_one_probe() {
        assert!(TcpProbeLoopOptions::default().validate().is_ok());
        assert!(TcpProbeLoopOptions {
            claim_lease: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            ..TcpProbeLoopOptions::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn address_filter_rejects_ssrf_and_non_internet_ranges() {
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:20::1".parse::<Ipv6Addr>().unwrap()),
        ] {
            assert!(!is_publishable_address(address));
        }
        assert!(is_publishable_address(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(is_publishable_address(IpAddr::V6(
            "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[tokio::test]
    async fn system_executor_refuses_loopback_before_connecting() {
        let result = SystemTcpProbeExecutor
            .probe("127.0.0.1", 443, Duration::from_secs(1))
            .await;
        assert_eq!(
            result,
            TcpProbeResult::failed(TcpProbeErrorCode::TargetNotPublic)
        );
    }

    #[tokio::test]
    async fn remote_executor_sends_a_bounded_authenticated_request() {
        let router = Router::new().route(
            "/v1/tcp-probe",
            post(
                |headers: HeaderMap, Json(request): Json<TcpProbeExecutorRequest>| async move {
                    assert_eq!(
                        headers
                            .get(header::AUTHORIZATION)
                            .unwrap()
                            .to_str()
                            .unwrap(),
                        format!("Bearer {REMOTE_TOKEN}")
                    );
                    request.validate().unwrap();
                    Json(TcpProbeExecutorResponse {
                        schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
                        request_id: request.request_id,
                        result: TcpProbeExecutorResult::Connected {
                            resolved_address: request.targets[0],
                            latency_millis: 11,
                        },
                    })
                },
            ),
        );
        let endpoint = spawn_mock_executor(router).await;
        let executor = remote_test_executor(&endpoint);
        let result = executor.probe("8.8.8.8", 443, Duration::from_secs(1)).await;
        assert_eq!(
            result,
            TcpProbeResult::connected(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                Duration::from_millis(11)
            )
        );
        assert_eq!(
            executor
                .probe("127.0.0.1", 443, Duration::from_secs(1))
                .await,
            TcpProbeResult::failed(TcpProbeErrorCode::TargetNotPublic)
        );
        assert_eq!(
            executor
                .probe("2606:4700:4700::1111", 443, Duration::from_secs(1))
                .await,
            TcpProbeResult::failed(TcpProbeErrorCode::NoSupportedAddress)
        );
    }

    #[tokio::test]
    async fn remote_executor_rejects_unbound_or_oversized_responses() {
        let unbound = Router::new().route(
            "/v1/tcp-probe",
            post(|Json(request): Json<TcpProbeExecutorRequest>| async move {
                Json(TcpProbeExecutorResponse {
                    schema_version: TCP_PROBE_EXECUTOR_SCHEMA_VERSION,
                    request_id: request.request_id,
                    result: TcpProbeExecutorResult::Connected {
                        resolved_address: Ipv4Addr::new(9, 9, 9, 9),
                        latency_millis: 1,
                    },
                })
            }),
        );
        let endpoint = spawn_mock_executor(unbound).await;
        assert_eq!(
            remote_test_executor(&endpoint)
                .probe("8.8.8.8", 443, Duration::from_secs(1))
                .await,
            TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed)
        );

        let oversized = Router::new().route(
            "/v1/tcp-probe",
            post(|| async {
                (
                    [(header::CONTENT_TYPE, "application/json")],
                    "a".repeat(9 * 1024),
                )
            }),
        );
        let endpoint = spawn_mock_executor(oversized).await;
        assert_eq!(
            remote_test_executor(&endpoint)
                .probe("8.8.8.8", 443, Duration::from_secs(1))
                .await,
            TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed)
        );

        let redirect = Router::new()
            .route(
                "/v1/tcp-probe",
                post(|| async { Redirect::temporary("/redirected") }),
            )
            .route("/redirected", post(panic_if_redirected));
        let endpoint = spawn_mock_executor(redirect).await;
        assert_eq!(
            remote_test_executor(&endpoint)
                .probe("8.8.8.8", 443, Duration::from_secs(1))
                .await,
            TcpProbeResult::failed(TcpProbeErrorCode::ExecutorFailed)
        );
    }

    fn remote_test_executor(endpoint: &str) -> RemoteHttpTcpProbeExecutor {
        RemoteHttpTcpProbeExecutor::new(RemoteTcpProbeConfig::for_test(endpoint, REMOTE_TOKEN))
            .unwrap()
    }

    async fn spawn_mock_executor(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}/v1/tcp-probe")
    }

    async fn panic_if_redirected() -> StatusCode {
        panic!("remote executor must not follow redirects");
    }
}
