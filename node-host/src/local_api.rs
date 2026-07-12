use crate::{
    HostStatus, RelayAssignmentState, RelayAssignmentStatus, RelayRuntimeState, RouterMappingStatus,
};
use anyhow::{Context as _, Result};
#[cfg(target_os = "macos")]
use control_protocol::id::RequestId;
use control_protocol::id::{NodeId, Revision, Timestamp};
use control_protocol::node::{
    EndpointReadiness, NodeHeartbeatStatus, NodeLifecycleState, NodeRuntimeState,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

pub(crate) const LOCAL_API_SCHEMA_VERSION: u16 = 3;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_REQUEST_MAX_BYTES: usize = 4 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_RESPONSE_MAX_BYTES: usize = 32 * 1024;
#[cfg(target_os = "macos")]
pub(crate) const LOCAL_API_SOCKET_FILE: &str = "node-host.sock";

/// Current high-level phase of the local Node Host service process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalServicePhase {
    /// Service process is recovering durable state.
    Starting,
    /// Service is reconciling with Control.
    Syncing,
    /// No healthy public data path is active.
    Idle,
    /// The managed public data path is healthy.
    Serving,
    /// A legacy or warning state is serving without the full public gate.
    Degraded,
    /// The provider locally paused new traffic.
    Paused,
    /// A local security condition prevents operation.
    Quarantined,
    /// A bounded retry is scheduled after a failed cycle.
    Retrying,
    /// The service is releasing mappings and stopping managed Xray.
    Stopping,
    /// The local runtime has been fully stopped.
    Stopped,
}

impl LocalServicePhase {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Syncing => "syncing",
            Self::Idle => "idle",
            Self::Serving => "serving",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retrying => "retrying",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
        }
    }
}

impl fmt::Display for LocalServicePhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Provider-facing progress for the complete one-action setup journey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeSetupPhase {
    /// Background service is starting or has not completed its first sync.
    Starting,
    /// Control has enrolled the identity but has not activated it.
    WaitingForApproval,
    /// The node is active but has not fetched a first desired revision.
    WaitingForConfiguration,
    /// A desired revision is being received, validated, or activated.
    ApplyingConfiguration,
    /// Local service is healthy and establishing a direct or relay endpoint.
    EstablishingReachability,
    /// Control is checking a reported endpoint from outside the node network.
    WaitingForVerification,
    /// A protocol-verified endpoint is ready for member publication.
    Ready,
    /// Provider pause is active.
    Paused,
    /// A local failure or quarantine requires provider attention.
    NeedsAttention,
}

impl NodeSetupPhase {
    /// Returns the stable wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::WaitingForApproval => "waitingForApproval",
            Self::WaitingForConfiguration => "waitingForConfiguration",
            Self::ApplyingConfiguration => "applyingConfiguration",
            Self::EstablishingReachability => "establishingReachability",
            Self::WaitingForVerification => "waitingForVerification",
            Self::Ready => "ready",
            Self::Paused => "paused",
            Self::NeedsAttention => "needsAttention",
        }
    }
}

impl fmt::Display for NodeSetupPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Stable, secret-free failure categories exposed by the local service API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalServiceErrorCode {
    /// Managed Xray recovery failed before the normal loop started.
    XrayRecoveryFailed,
    /// A full sync, activation, or mapping reconciliation cycle failed.
    SyncCycleFailed,
    /// A running Xray or admission-gate health check failed.
    RuntimeHealthFailed,
}

impl LocalServiceErrorCode {
    /// Returns the stable diagnostic value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XrayRecoveryFailed => "xray_recovery_failed",
            Self::SyncCycleFailed => "sync_cycle_failed",
            Self::RuntimeHealthFailed => "runtime_health_failed",
        }
    }
}

impl fmt::Display for LocalServiceErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Last safe local service failure, without the underlying error text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalServiceError {
    /// Stable UI and diagnostic contract.
    pub code: LocalServiceErrorCode,
    /// Local observation time for the failure.
    pub occurred_at: Timestamp,
}

impl LocalServiceError {
    pub(crate) fn now(code: LocalServiceErrorCode) -> Self {
        Self {
            code,
            occurred_at: now(),
        }
    }
}

/// Non-secret live Node Host state returned to the same-user owner UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalServiceStatus {
    /// Local API schema version.
    pub schema_version: u16,
    /// Random identity for this service-process lifetime.
    pub service_instance_id: Uuid,
    /// Time this complete snapshot was observed.
    pub observed_at: Timestamp,
    /// Current service-loop phase.
    pub phase: LocalServicePhase,
    /// Stable enrolled node identity.
    pub node_id: NodeId,
    /// Current managed Xray/admission state.
    pub runtime_state: NodeRuntimeState,
    /// Last heartbeat durably acknowledged by Control.
    pub last_heartbeat_at: Option<Timestamp>,
    /// Latest locally verified controller lifecycle and endpoint readiness.
    pub controller_status: Option<NodeHeartbeatStatus>,
    /// Last complete synchronization cycle.
    pub last_sync_at: Option<Timestamp>,
    /// Highest desired-state revision durably accepted locally.
    pub desired_revision_cursor: i64,
    /// Last revision that passed local activation health checks.
    pub applied_revision: Option<Revision>,
    /// Latest safe activation-journal phase.
    pub activation_phase: Option<String>,
    /// Whether a checksum-pinned Xray runtime is configured.
    pub xray_configured: bool,
    /// Current provider-owned router mapping state.
    pub router_mapping: RouterMappingStatus,
    /// Current safe relay assignment metadata.
    pub relay_assignment: RelayAssignmentStatus,
    /// Live relay connector lifecycle owned by this service process.
    pub relay_runtime: RelayRuntimeState,
    /// Last categorized service-loop failure, if it has not yet recovered.
    pub last_error: Option<LocalServiceError>,
}

impl LocalServiceStatus {
    /// Derives setup progress without overstating local or TCP-only evidence.
    #[must_use]
    pub fn setup_phase(&self) -> NodeSetupPhase {
        if self.phase == LocalServicePhase::Paused {
            return NodeSetupPhase::Paused;
        }
        if self.last_error.is_some()
            || matches!(
                self.phase,
                LocalServicePhase::Degraded | LocalServicePhase::Quarantined
            )
        {
            return NodeSetupPhase::NeedsAttention;
        }
        let Some(controller) = &self.controller_status else {
            return NodeSetupPhase::Starting;
        };
        if controller.lifecycle == NodeLifecycleState::Pending {
            return NodeSetupPhase::WaitingForApproval;
        }
        if self.desired_revision_cursor == 0 {
            return NodeSetupPhase::WaitingForConfiguration;
        }
        if self.applied_revision.map(Revision::get) != Some(self.desired_revision_cursor)
            || self.runtime_state != NodeRuntimeState::Serving
        {
            return NodeSetupPhase::ApplyingConfiguration;
        }
        if controller
            .endpoints
            .iter()
            .any(|endpoint| endpoint.readiness == EndpointReadiness::Verified)
        {
            return NodeSetupPhase::Ready;
        }
        if controller.endpoints.is_empty() {
            NodeSetupPhase::EstablishingReachability
        } else {
            NodeSetupPhase::WaitingForVerification
        }
    }

    pub(crate) fn from_host(
        service_instance_id: Uuid,
        host: &HostStatus,
        phase: LocalServicePhase,
        runtime_state: NodeRuntimeState,
        relay_runtime: RelayRuntimeState,
        last_error: Option<LocalServiceError>,
    ) -> Result<Self> {
        let status = Self {
            schema_version: LOCAL_API_SCHEMA_VERSION,
            service_instance_id,
            observed_at: now(),
            phase,
            node_id: host
                .node_id
                .context("enrolled Node Host status has no node identity")?,
            runtime_state,
            last_heartbeat_at: host.last_heartbeat_at,
            controller_status: host.controller_status.clone(),
            last_sync_at: host.last_sync_at,
            desired_revision_cursor: host.desired_revision_cursor,
            applied_revision: host.applied_revision,
            activation_phase: host.xray_activation_phase.clone(),
            xray_configured: host.xray_configured,
            router_mapping: host.router_mapping.clone(),
            relay_assignment: host.relay.clone(),
            relay_runtime,
            last_error,
        };
        status.validate()?;
        Ok(status)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != LOCAL_API_SCHEMA_VERSION {
            anyhow::bail!("unsupported local service status schema");
        }
        if self.desired_revision_cursor < 0 {
            anyhow::bail!("local service desired revision cannot be negative");
        }
        if self.service_instance_id.is_nil() {
            anyhow::bail!("local service instance identity cannot be nil");
        }
        if let Some(controller_status) = &self.controller_status {
            controller_status
                .validate_for(
                    self.node_id,
                    controller_status.heartbeat_generation,
                    controller_status.controller_instance_id,
                )
                .context("local service controller status is invalid")?;
        }
        if self.relay_runtime == RelayRuntimeState::Registered
            && (self.runtime_state != NodeRuntimeState::Serving
                || self.relay_assignment.state != RelayAssignmentState::Configured)
        {
            anyhow::bail!("registered relay requires a serving runtime and current assignment");
        }
        if self
            .activation_phase
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self
                .router_mapping
                .last_error_code
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self
                .router_mapping
                .external_address
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 253)
        {
            anyhow::bail!("local service status contains invalid bounded text");
        }
        match self.phase {
            LocalServicePhase::Serving if self.runtime_state != NodeRuntimeState::Serving => {
                anyhow::bail!("serving phase requires a serving runtime");
            }
            LocalServicePhase::Degraded if self.runtime_state != NodeRuntimeState::Degraded => {
                anyhow::bail!("degraded phase requires a degraded runtime");
            }
            LocalServicePhase::Idle
                if !matches!(
                    self.runtime_state,
                    NodeRuntimeState::Idle | NodeRuntimeState::Pending
                ) =>
            {
                anyhow::bail!("idle phase requires an idle or pending runtime");
            }
            LocalServicePhase::Paused if self.runtime_state != NodeRuntimeState::ProviderPaused => {
                anyhow::bail!("paused phase requires a provider-paused runtime");
            }
            LocalServicePhase::Quarantined
                if self.runtime_state != NodeRuntimeState::Quarantined =>
            {
                anyhow::bail!("quarantined phase requires a quarantined runtime");
            }
            LocalServicePhase::Stopped if self.runtime_state != NodeRuntimeState::Stopped => {
                anyhow::bail!("stopped phase requires a stopped runtime");
            }
            _ => {}
        }
        Ok(())
    }
}

/// Safe provider-facing setup status returned by the desktop backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeSetupStatus {
    /// Derived end-to-end progress.
    pub setup_phase: NodeSetupPhase,
    /// Complete safe local service snapshot used to explain that progress.
    pub local: LocalServiceStatus,
}

pub(crate) fn phase_for_runtime(runtime_state: NodeRuntimeState) -> LocalServicePhase {
    match runtime_state {
        NodeRuntimeState::Pending | NodeRuntimeState::Idle => LocalServicePhase::Idle,
        NodeRuntimeState::Serving => LocalServicePhase::Serving,
        NodeRuntimeState::ProviderPaused => LocalServicePhase::Paused,
        NodeRuntimeState::Degraded => LocalServicePhase::Degraded,
        NodeRuntimeState::Quarantined => LocalServicePhase::Quarantined,
        NodeRuntimeState::Stopped => LocalServicePhase::Stopped,
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum LocalApiMethod {
    Status,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalApiRequest {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub method: LocalApiMethod,
}

#[cfg(target_os = "macos")]
impl LocalApiRequest {
    pub(crate) fn status() -> Self {
        Self {
            schema_version: LOCAL_API_SCHEMA_VERSION,
            request_id: RequestId::new(),
            method: LocalApiMethod::Status,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalApiResponse {
    pub schema_version: u16,
    pub request_id: RequestId,
    pub status: LocalServiceStatus,
}

/// Queries the live local Node Host service through its same-user IPC channel.
///
/// This reports process and local data-plane state plus the latest persisted
/// controller status after local signature verification. Approval and endpoint
/// verification are never inferred from local runtime state.
///
/// # Errors
///
/// Returns an error when the platform is unsupported, the service is not
/// running, socket ownership is unsafe, framing is invalid, the request times
/// out, or the response is not bound to this request.
pub async fn query_local_service_status(data_dir: &Path) -> Result<LocalServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        crate::local_api_macos::query(data_dir).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data_dir;
        anyhow::bail!("the local Node Host status API is not implemented on this platform");
    }
}

/// Queries the service and derives conservative one-action setup progress.
///
/// # Errors
///
/// Returns the same errors as [`query_local_service_status`].
pub async fn query_node_setup_status(data_dir: &Path) -> Result<NodeSetupStatus> {
    let local = query_local_service_status(data_dir).await?;
    Ok(NodeSetupStatus {
        setup_phase: local.setup_phase(),
        local,
    })
}

#[cfg(target_os = "macos")]
pub(crate) use crate::local_api_macos::LocalStatusServer;

#[cfg(not(target_os = "macos"))]
pub(crate) struct LocalStatusServer;

#[cfg(not(target_os = "macos"))]
impl LocalStatusServer {
    pub(crate) fn start(_data_dir: &Path, _initial: LocalServiceStatus) -> Result<Self> {
        Ok(Self)
    }

    pub(crate) fn publish(&self, status: LocalServiceStatus) -> Result<()> {
        status.validate()
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        Ok(())
    }
}

fn now() -> Timestamp {
    Timestamp::from_datetime(OffsetDateTime::now_utc())
}
