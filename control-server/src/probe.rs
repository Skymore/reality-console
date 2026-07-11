use crate::db::{Database, DatabaseError};
use async_trait::async_trait;
use control_protocol::id::{EndpointId, NetworkId, NodeId, Revision};
use control_protocol::secret::Secret;
use std::collections::BTreeSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Instant};
use uuid::Uuid;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(30);
const DEFAULT_SUCCESS_INTERVAL: Duration = Duration::from_secs(15 * 60);
const DEFAULT_FAILURE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_NODE_ONLINE_WINDOW: Duration = Duration::from_secs(90);
const MAX_RESOLVED_ADDRESSES: usize = 16;

/// Selects whether this process executes endpoint probes itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// Store candidates without executing probes in the controller process.
    Disabled,
    /// Execute TCP preflight from this process. This is valid only when the
    /// controller is outside the candidate node's LAN.
    LocalTcp,
}

impl FromStr for ProbeMode {
    type Err = ProbeModeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "local-tcp" => Ok(Self::LocalTcp),
            _ => Err(ProbeModeParseError),
        }
    }
}

/// Invalid `CONTROL_PROBE_MODE` value.
#[derive(Debug, Error)]
#[error("invalid probe mode")]
pub struct ProbeModeParseError;

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
    let runner_id = Uuid::new_v4();
    let executor = SystemTcpProbeExecutor;
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
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        && octets[0] != 0
        && octets[0] < 240
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeServiceError {
    #[error("TCP probe loop timing options are invalid")]
    InvalidOptions,
}

#[cfg(test)]
mod tests {
    use super::{
        is_publishable_address, ProbeMode, SystemTcpProbeExecutor, TcpProbeErrorCode,
        TcpProbeExecutor, TcpProbeLoopOptions, TcpProbeResult,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr as _;
    use std::time::Duration;

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
        assert!(ProbeMode::from_str("tcp").is_err());
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
}
