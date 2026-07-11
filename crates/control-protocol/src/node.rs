//! Node invitation, enrollment, heartbeat, and desired-state contracts.

use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest, X25519PublicKey};
use crate::error::ErrorCode;
use crate::id::{
    ControllerInstanceId, CredentialId, EndpointId, NetworkId, NodeId, NodeInvitationId, NodeKeyId,
    Revision, SequenceNumber, SigningKeyId, Timestamp, UserId,
};
use crate::secret::Secret;
use crate::validation::{ProtocolValidationError, ValidationCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Maximum lifetime accepted for a node invitation.
pub const MAX_NODE_INVITATION_LIFETIME_SECONDS: u32 = 3_600;

/// Admin request to create a one-time node invitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateNodeInvitationRequest {
    /// Operator-facing intended node name.
    pub display_name: String,
    /// Requested validity period in seconds.
    pub expires_in_seconds: u32,
}

impl CreateNodeInvitationRequest {
    /// Validates bounded invitation metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the display name is invalid or the requested
    /// lifetime is outside the protocol bound.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_display_name(&self.display_name, "displayName")?;
        if !(1..=MAX_NODE_INVITATION_LIFETIME_SECONDS).contains(&self.expires_in_seconds) {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "expiresInSeconds",
                "invitation lifetime must be between 1 and 3600 seconds",
            ));
        }
        Ok(())
    }
}

/// One-time node invitation returned only at creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNodeInvitationResponse {
    /// Stable invitation identity.
    pub invitation_id: NodeInvitationId,
    /// Pairing purpose, preventing cross-purpose use.
    pub purpose: PairingPurpose,
    /// Absolute invitation expiry.
    pub expires_at: Timestamp,
    /// High-entropy single-use enrollment secret.
    pub invitation_secret: Secret<String>,
    /// Controller origin pinned into the enrollment transcript.
    pub controller_origin: String,
    /// Controller TLS or enrollment-key fingerprint.
    pub controller_fingerprint: Sha256Digest,
}

/// Closed pairing purposes; credentials are never interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PairingPurpose {
    /// Enroll a Node Host installation.
    NodeEnrollment,
    /// Activate a member Connect device.
    DeviceActivation,
    /// Enroll an administrator device.
    AdminDeviceEnrollment,
}

/// Closed capabilities a node may advertise during enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeCapability {
    /// Manage the pinned Xray sidecar.
    Xray,
    /// Expose a direct raw TCP endpoint.
    DirectTcp,
    /// Request consent-gated `UPnP` mapping.
    Upnp,
    /// Request consent-gated NAT-PMP mapping.
    NatPmp,
    /// Request consent-gated PCP mapping.
    Pcp,
    /// Use an assigned raw TCP relay.
    RelayTcp,
}

/// Request that atomically consumes a node invitation and binds public keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollNodeRequest {
    /// High-entropy single-use invitation value.
    pub invitation_secret: Secret<String>,
    /// Node Host semantic version.
    pub agent_version: String,
    /// Closed deployment platform identifier such as `macos-arm64`.
    pub platform: String,
    /// Provider-selected node name.
    pub display_name: String,
    /// Closed set of locally supported features.
    pub capabilities: Vec<NodeCapability>,
    /// Locally generated Ed25519 request-signing identity.
    pub identity_public_key: Ed25519PublicKey,
    /// Locally generated X25519 recipient-encryption identity.
    pub encryption_public_key: X25519PublicKey,
    /// Fresh client nonce included in the enrollment transcript.
    pub nonce: Nonce,
    /// Signature over the complete enrollment transcript.
    pub proof: Ed25519Signature,
    /// Versioned consent statement accepted by the node provider.
    pub provider_consent: ProviderConsent,
}

impl EnrollNodeRequest {
    /// Validates bounded enrollment metadata before cryptographic verification.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty invitation, invalid bounded metadata,
    /// duplicate capabilities, or incomplete provider consent.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.invitation_secret.expose_secret().is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "invitationSecret",
                "invitation secret is required",
            ));
        }
        validate_short_text(&self.agent_version, 64, "agentVersion")?;
        validate_short_text(&self.platform, 64, "platform")?;
        validate_display_name(&self.display_name, "displayName")?;
        if self.capabilities.is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "capabilities",
                "at least one capability is required",
            ));
        }
        if self.capabilities.len() > 16
            || self
                .capabilities
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len()
                != self.capabilities.len()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "capabilities",
                "capabilities must be unique and bounded",
            ));
        }
        let has_mapping_capability = self.capabilities.iter().any(|capability| {
            matches!(
                capability,
                NodeCapability::Upnp | NodeCapability::NatPmp | NodeCapability::Pcp
            )
        });
        if has_mapping_capability != self.provider_consent.router_mapping_accepted
            || (has_mapping_capability && !self.capabilities.contains(&NodeCapability::DirectTcp))
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "capabilities",
                "router mapping capabilities require matching consent and direct TCP support",
            ));
        }
        self.provider_consent.validate()
    }
}

/// Provider consent recorded as part of node enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderConsent {
    /// Version of the disclosure accepted by the provider.
    pub policy_version: String,
    /// Confirms authorization to operate the host.
    pub host_owner_consented: bool,
    /// Confirms acknowledgement that the public IP becomes an exit IP.
    pub exit_ip_disclosure_accepted: bool,
    /// Permits this installation to request a narrow router port mapping.
    pub router_mapping_accepted: bool,
    /// Time of local acceptance.
    pub accepted_at: Timestamp,
}

impl ProviderConsent {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_short_text(&self.policy_version, 64, "providerConsent.policyVersion")?;
        if !self.host_owner_consented || !self.exit_ip_disclosure_accepted {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "providerConsent",
                "host-owner consent and exit-IP disclosure are required",
            ));
        }
        Ok(())
    }
}

/// Authentication mode issued to an enrolled node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeAuthenticationMode {
    /// The node authenticates with a short-lived client certificate.
    MutualTls,
    /// The node signs every request end to end with its enrolled identity key.
    SignedRequest,
}

/// First credential metadata issued to an enrolled node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeCredential {
    /// Controller-assigned key record identity.
    pub key_id: NodeKeyId,
    /// Authentication mechanism authorized for the key.
    pub mode: NodeAuthenticationMode,
    /// Credential expiry.
    pub expires_at: Timestamp,
    /// Optional public client-certificate chain for mTLS mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_certificate_pem: Option<String>,
}

/// Successful node enrollment response bound to the enrollment transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollNodeResponse {
    /// Network the invitation enrolled into.
    pub network_id: NetworkId,
    /// Unique identity assigned to this installation.
    pub node_id: NodeId,
    /// Controller epoch used to fence restored controllers.
    pub controller_instance_id: ControllerInstanceId,
    /// Initial node authentication credential.
    pub credential: NodeCredential,
    /// Controller desired-state signing public key.
    pub desired_state_signing_public_key: Ed25519PublicKey,
    /// Fresh controller nonce bound by the response proof.
    pub controller_nonce: Nonce,
    /// Controller signature binding both nonces, keys, purpose, and invitation.
    pub proof: Ed25519Signature,
}

/// Current high-level Node Host state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeRuntimeState {
    /// Enrolled but not yet approved or configured.
    Pending,
    /// Ready but not currently serving member traffic.
    Idle,
    /// Serving the last successfully applied configuration.
    Serving,
    /// Locally paused by the provider.
    ProviderPaused,
    /// Serving with a health or synchronization warning.
    Degraded,
    /// Identity collision or security policy prevents operation.
    Quarantined,
    /// Locally stopped or removed.
    Stopped,
}

/// Data-path endpoint mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointMode {
    /// Connect reaches the node endpoint directly.
    Direct,
    /// Connect reaches the node through an opaque raw TCP relay.
    Relay,
}

/// Node-observed origin of an endpoint candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointSource {
    /// Existing provider endpoint or explicit router forwarding.
    Manual,
    /// Port Control Protocol mapping.
    Pcp,
    /// NAT Port Mapping Protocol mapping.
    NatPmp,
    /// `UPnP` Internet Gateway Device mapping.
    Upnp,
    /// Controller-assigned opaque raw-TCP relay.
    Relay,
}

/// Controller-observed endpoint verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointStatus {
    /// Not yet externally probed.
    Pending,
    /// Externally reachable in the reported mode.
    Verified,
    /// The most recent external probe failed.
    Failed,
    /// No longer eligible for advertisement.
    Withdrawn,
}

/// Unverified endpoint candidate reported by a node heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointCandidate {
    /// Stable identity for this exact candidate and lease generation.
    pub endpoint_id: EndpointId,
    /// Direct or relay path.
    pub mode: EndpointMode,
    /// How the node obtained this candidate.
    pub source: EndpointSource,
    /// Hostname or IP address, never a general URL.
    pub address: String,
    /// TCP port.
    pub port: u16,
    /// Applied Xray revision served by this candidate.
    pub applied_revision: Revision,
    /// Time the node observed or created this candidate.
    pub observed_at: Timestamp,
    /// Mapping or relay lease expiry. Manual endpoints may omit it.
    pub expires_at: Option<Timestamp>,
}

impl EndpointCandidate {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_short_text(&self.address, 253, "endpoints.address")?;
        if self.address.contains('/') || self.address.contains(char::is_whitespace) {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidFormat,
                "endpoints.address",
                "endpoint address must be a hostname or IP address, not a URL",
            ));
        }
        if self.port == 0 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "endpoints.port",
                "endpoint port must be non-zero",
            ));
        }
        let source_matches_mode = matches!(
            (self.mode, self.source),
            (
                EndpointMode::Direct,
                EndpointSource::Manual
                    | EndpointSource::Pcp
                    | EndpointSource::NatPmp
                    | EndpointSource::Upnp
            ) | (EndpointMode::Relay, EndpointSource::Relay)
        );
        if !source_matches_mode {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "endpoints.source",
                "endpoint source must agree with direct or relay mode",
            ));
        }
        if self
            .expires_at
            .is_some_and(|expiry| expiry <= self.observed_at)
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "endpoints.expiresAt",
                "endpoint expiry must be later than its observation time",
            ));
        }
        if self.source != EndpointSource::Manual && self.expires_at.is_none() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "endpoints.expiresAt",
                "mapped and relayed endpoint candidates require a finite expiry",
            ));
        }
        Ok(())
    }
}

/// Monotonic desired-state progress reported by Node Host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionProgress {
    /// Latest revision offered by the controller and persisted by the node.
    pub desired_revision: Option<Revision>,
    /// Latest revision durably received.
    pub received_revision: Option<Revision>,
    /// Latest revision whose generated configuration validated.
    pub validated_revision: Option<Revision>,
    /// Revision currently running after health check or rollback.
    pub applied_revision: Option<Revision>,
}

impl RevisionProgress {
    /// Validates `desired >= received >= validated >= applied` and presence.
    ///
    /// # Errors
    ///
    /// Returns an error when a lifecycle cursor exists without its predecessor
    /// or exceeds that predecessor's revision.
    pub fn validate(self) -> Result<(), ProtocolValidationError> {
        validate_revision_pair(
            self.desired_revision,
            self.received_revision,
            "receivedRevision",
        )?;
        validate_revision_pair(
            self.received_revision,
            self.validated_revision,
            "validatedRevision",
        )?;
        validate_revision_pair(
            self.validated_revision,
            self.applied_revision,
            "appliedRevision",
        )
    }
}

/// Current-state heartbeat from Node Host; it is not a command envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeHeartbeat {
    /// Durable, monotonically increasing identity of this complete snapshot.
    pub heartbeat_generation: SequenceNumber,
    /// Node Host semantic version.
    pub agent_version: String,
    /// Running Xray version, when installed.
    pub xray_version: Option<String>,
    /// Current high-level state.
    pub state: NodeRuntimeState,
    /// Desired-state progress.
    #[serde(flatten)]
    pub revisions: RevisionProgress,
    /// Provider-local pause always takes effect without controller access.
    pub provider_paused: bool,
    /// Bounded unverified endpoint candidates.
    pub endpoints: Vec<EndpointCandidate>,
    /// Highest telemetry sequence retained or acknowledged locally.
    pub telemetry_cursor: SequenceNumber,
}

impl NodeHeartbeat {
    /// Validates heartbeat consistency and bounded text/collections.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid versions, inconsistent revision progress,
    /// pause-state disagreement, too many endpoints, or an invalid endpoint.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.heartbeat_generation.get() == 0 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "heartbeatGeneration",
                "heartbeat generation must be positive",
            ));
        }
        validate_short_text(&self.agent_version, 64, "agentVersion")?;
        if let Some(version) = &self.xray_version {
            validate_short_text(version, 64, "xrayVersion")?;
        }
        self.revisions.validate()?;
        if self.provider_paused != (self.state == NodeRuntimeState::ProviderPaused) {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "providerPaused",
                "providerPaused must agree with the runtime state",
            ));
        }
        if self.endpoints.len() > 16 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "endpoints",
                "heartbeat endpoint count exceeds the protocol bound",
            ));
        }
        if self
            .endpoints
            .iter()
            .map(|endpoint| endpoint.endpoint_id)
            .collect::<HashSet<_>>()
            .len()
            != self.endpoints.len()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "endpoints",
                "endpoint candidate identities must be unique",
            ));
        }
        if self
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.mode,
                    endpoint.address.as_str(),
                    endpoint.port,
                    endpoint.applied_revision,
                )
            })
            .collect::<HashSet<_>>()
            .len()
            != self.endpoints.len()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "endpoints",
                "endpoint candidates must not repeat an address for one revision",
            ));
        }
        if !self.endpoints.is_empty() && self.state != NodeRuntimeState::Serving {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "endpoints",
                "only a serving node may report endpoint candidates",
            ));
        }
        for endpoint in &self.endpoints {
            endpoint.validate()?;
            if Some(endpoint.applied_revision) != self.revisions.applied_revision {
                return Err(ProtocolValidationError::new(
                    ValidationCode::InconsistentState,
                    "endpoints.appliedRevision",
                    "endpoint candidate must match the heartbeat applied revision",
                ));
            }
        }
        Ok(())
    }
}

/// Per-member credential in a node's signed desired state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesiredUser {
    /// Stable logical member identity.
    pub user_id: UserId,
    /// Stable per-user, per-node credential identity.
    pub credential_id: CredentialId,
    /// Node-specific VLESS UUID bearer secret.
    pub vless_uuid: Secret<String>,
    /// Whether the credential may serve traffic.
    pub enabled: bool,
}

/// Closed Xray configuration fields centrally controlled for a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesiredXrayState {
    /// Node-local loopback port used only by the managed Xray inbound.
    pub listen_port: u16,
    /// Public admission-gate TCP port. Absent only in legacy schema version 1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_public_port"
    )]
    pub public_port: Option<u16>,
    /// REALITY server names accepted by this node.
    pub server_names: Vec<String>,
    /// REALITY fallback target in `host:port` form.
    pub target: String,
}

fn deserialize_present_public_port<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    u16::deserialize(deserializer).map(Some)
}

/// Immutable desired-state document for one node and revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesiredStateDocument {
    /// Desired-state schema version.
    pub schema_version: u16,
    /// Exact target private network.
    pub network_id: NetworkId,
    /// Exact target node.
    pub node_id: NodeId,
    /// Monotonic immutable revision.
    pub revision: Revision,
    /// Controller publication time.
    pub created_at: Timestamp,
    /// Minimum Node Host semantic version required to interpret this state.
    pub min_agent_version: String,
    /// Complete enabled/disabled member credential set.
    pub users: Vec<DesiredUser>,
    /// Closed centrally managed Xray fields.
    pub xray: DesiredXrayState,
    /// Public key identifier used to sign this artifact.
    pub signing_key_id: SigningKeyId,
    /// Controller epoch used to prevent restore rollback.
    pub controller_instance_id: ControllerInstanceId,
}

/// Signature envelope for one immutable desired-state document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedDesiredState {
    /// Closed document covered by the controller signature.
    pub document: DesiredStateDocument,
    /// Signature over the canonical unsigned document.
    pub signature: Ed25519Signature,
}

impl DesiredStateDocument {
    /// Validates shape, target, schema support, and monotonicity.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schema, a different target node, a
    /// stale revision, duplicate identities, missing credentials, or invalid
    /// bounded Xray fields.
    pub fn validate_for(
        &self,
        expected_network_id: NetworkId,
        expected_node_id: NodeId,
        expected_controller_instance_id: ControllerInstanceId,
        last_seen_revision: Option<Revision>,
        supported_schema_versions: &[u16],
    ) -> Result<(), ProtocolValidationError> {
        if !supported_schema_versions.contains(&self.schema_version) {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "schemaVersion",
                "desired-state schema version is not supported",
            ));
        }
        if self.network_id != expected_network_id {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "networkId",
                "desired state is addressed to another network",
            ));
        }
        if self.node_id != expected_node_id {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "nodeId",
                "desired state is addressed to another node",
            ));
        }
        if self.controller_instance_id != expected_controller_instance_id {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "controllerInstanceId",
                "desired state belongs to another controller epoch",
            ));
        }
        if last_seen_revision.is_some_and(|last| self.revision <= last) {
            return Err(ProtocolValidationError::new(
                ValidationCode::StaleState,
                "revision",
                "desired-state revision is not newer than local state",
            ));
        }
        validate_short_text(&self.min_agent_version, 64, "minAgentVersion")?;
        if self.users.len() > 10_000 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "users",
                "desired-state user count exceeds the protocol bound",
            ));
        }
        let mut user_ids = HashSet::with_capacity(self.users.len());
        let mut credential_ids = HashSet::with_capacity(self.users.len());
        for user in &self.users {
            if !user_ids.insert(user.user_id) || !credential_ids.insert(user.credential_id) {
                return Err(ProtocolValidationError::new(
                    ValidationCode::DuplicateIdentity,
                    "users",
                    "user and credential IDs must be unique within desired state",
                ));
            }
            let vless_uuid = user.vless_uuid.expose_secret();
            let canonical_uuid = uuid::Uuid::parse_str(vless_uuid)
                .map(|value| value.hyphenated().to_string() == *vless_uuid)
                .unwrap_or(false);
            if !canonical_uuid {
                return Err(ProtocolValidationError::new(
                    ValidationCode::InvalidFormat,
                    "users.vlessUuid",
                    "VLESS credential must be a canonical lowercase UUID",
                ));
            }
        }
        self.xray.validate(self.schema_version)
    }
}

impl SignedDesiredState {
    /// Validates the enclosed document without verifying its signature.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`DesiredStateDocument::validate_for`].
    pub fn validate_for(
        &self,
        expected_network_id: NetworkId,
        expected_node_id: NodeId,
        expected_controller_instance_id: ControllerInstanceId,
        last_seen_revision: Option<Revision>,
        supported_schema_versions: &[u16],
    ) -> Result<(), ProtocolValidationError> {
        self.document.validate_for(
            expected_network_id,
            expected_node_id,
            expected_controller_instance_id,
            last_seen_revision,
            supported_schema_versions,
        )
    }
}

impl DesiredXrayState {
    fn validate(&self, schema_version: u16) -> Result<(), ProtocolValidationError> {
        if self.listen_port == 0 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "xray.listenPort",
                "Xray listen port must be non-zero",
            ));
        }
        match schema_version {
            1 if self.public_port.is_some() => {
                return Err(ProtocolValidationError::new(
                    ValidationCode::InconsistentState,
                    "xray.publicPort",
                    "desired-state schema version 1 cannot carry a public admission port",
                ));
            }
            1 => {}
            2 => {
                let public_port = self.public_port.ok_or_else(|| {
                    ProtocolValidationError::new(
                        ValidationCode::MissingField,
                        "xray.publicPort",
                        "desired-state schema version 2 requires a public admission port",
                    )
                })?;
                if public_port == 0 {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::OutOfRange,
                        "xray.publicPort",
                        "public admission port must be non-zero",
                    ));
                }
                if self.listen_port < 1_024 {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::OutOfRange,
                        "xray.listenPort",
                        "schema version 2 loopback port must be unprivileged",
                    ));
                }
                if public_port == self.listen_port {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::InconsistentState,
                        "xray.publicPort",
                        "public admission and Xray loopback ports must differ",
                    ));
                }
            }
            _ => {
                return Err(ProtocolValidationError::new(
                    ValidationCode::UnsupportedSchema,
                    "schemaVersion",
                    "desired-state Xray schema version is not supported",
                ));
            }
        }
        if self.server_names.is_empty() || self.server_names.len() > 16 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "xray.serverNames",
                "one to sixteen REALITY server names are required",
            ));
        }
        for name in &self.server_names {
            validate_short_text(name, 253, "xray.serverNames")?;
        }
        validate_short_text(&self.target, 259, "xray.target")?;
        if !self.target.contains(':') || self.target.contains("//") {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidFormat,
                "xray.target",
                "Xray target must use host:port form",
            ));
        }
        Ok(())
    }
}

/// Monotonic result state for one desired-state revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevisionResultState {
    /// Artifact was durably received.
    Received,
    /// Generated Xray configuration validated.
    Validated,
    /// Candidate started and passed health checks.
    Applied,
    /// Artifact or generated configuration was rejected before activation.
    Rejected,
    /// Failed activation restored a prior known-good revision.
    RolledBack,
}

impl RevisionResultState {
    const fn rank(self) -> u8 {
        match self {
            Self::Received => 10,
            Self::Validated => 20,
            Self::Applied | Self::Rejected | Self::RolledBack => 30,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected | Self::RolledBack)
    }
}

/// Node report for one desired-state revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionResult {
    /// Monotonic result state.
    pub state: RevisionResultState,
    /// Digest of the generated active configuration, when available.
    pub config_digest: Option<Sha256Digest>,
    /// Start of the bounded apply attempt.
    pub started_at: Timestamp,
    /// Completion of this state.
    pub completed_at: Timestamp,
    /// Stable safe diagnostic for a rejected or rolled-back revision.
    pub error_code: Option<ErrorCode>,
    /// Prior revision restored after failure.
    pub rollback_revision: Option<Revision>,
}

impl RevisionResult {
    /// Validates state-dependent fields for the addressed revision.
    ///
    /// # Errors
    ///
    /// Returns an error when timestamps are reversed, required state fields are
    /// absent, prohibited fields are present, or a rollback does not target an
    /// earlier revision.
    pub fn validate(&self, revision: Revision) -> Result<(), ProtocolValidationError> {
        if self.completed_at < self.started_at {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "completedAt",
                "completion cannot precede start",
            ));
        }
        match self.state {
            RevisionResultState::Received => {
                require_absent(self.config_digest.as_ref(), "configDigest")?;
                require_absent(self.error_code.as_ref(), "errorCode")?;
                require_absent(self.rollback_revision.as_ref(), "rollbackRevision")?;
            }
            RevisionResultState::Validated | RevisionResultState::Applied => {
                require_present(self.config_digest.as_ref(), "configDigest")?;
                require_absent(self.error_code.as_ref(), "errorCode")?;
                require_absent(self.rollback_revision.as_ref(), "rollbackRevision")?;
            }
            RevisionResultState::Rejected => {
                require_present(self.error_code.as_ref(), "errorCode")?;
                require_absent(self.rollback_revision.as_ref(), "rollbackRevision")?;
            }
            RevisionResultState::RolledBack => {
                require_present(self.config_digest.as_ref(), "configDigest")?;
                require_present(self.error_code.as_ref(), "errorCode")?;
                let rollback = self.rollback_revision.ok_or_else(|| {
                    ProtocolValidationError::new(
                        ValidationCode::MissingField,
                        "rollbackRevision",
                        "rolled-back state requires the restored revision",
                    )
                })?;
                if rollback >= revision {
                    return Err(ProtocolValidationError::new(
                        ValidationCode::InconsistentState,
                        "rollbackRevision",
                        "rollback revision must precede the failed revision",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validates a monotonic transition from a previously committed result.
    ///
    /// Repeating an identical result is idempotent. A different report for the
    /// same state, a transition from a terminal state, or a rank regression is
    /// rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when the new result is not an identical retry or a
    /// monotonic transition to a higher lifecycle rank.
    pub fn validate_transition_from(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), ProtocolValidationError> {
        let Some(previous) = previous else {
            return Ok(());
        };
        if self == previous {
            return Ok(());
        }
        if self.state == previous.state
            || previous.state.is_terminal()
            || self.state.rank() <= previous.state.rank()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidTransition,
                "state",
                "revision result transition must move monotonically to a new state",
            ));
        }
        Ok(())
    }
}

fn validate_revision_pair(
    upper: Option<Revision>,
    lower: Option<Revision>,
    lower_field: &'static str,
) -> Result<(), ProtocolValidationError> {
    match (upper, lower) {
        (None, Some(_)) => Err(ProtocolValidationError::new(
            ValidationCode::InconsistentState,
            lower_field,
            "revision progress cannot skip a preceding lifecycle state",
        )),
        (Some(upper), Some(lower)) if lower > upper => Err(ProtocolValidationError::new(
            ValidationCode::InconsistentState,
            lower_field,
            "revision progress cannot exceed its preceding lifecycle state",
        )),
        _ => Ok(()),
    }
}

fn require_present<T>(
    value: Option<&T>,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if value.is_none() {
        return Err(ProtocolValidationError::new(
            ValidationCode::MissingField,
            field,
            "field is required for this revision result state",
        ));
    }
    Ok(())
}

fn require_absent<T>(
    value: Option<&T>,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if value.is_some() {
        return Err(ProtocolValidationError::new(
            ValidationCode::InconsistentState,
            field,
            "field is not permitted for this revision result state",
        ));
    }
    Ok(())
}

fn validate_display_name(value: &str, field: &'static str) -> Result<(), ProtocolValidationError> {
    validate_short_text(value, 128, field)
}

fn validate_short_text(
    value: &str,
    maximum_length: usize,
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if value.is_empty() {
        return Err(ProtocolValidationError::new(
            ValidationCode::MissingField,
            field,
            "value is required",
        ));
    }
    if value.len() > maximum_length || value.chars().any(char::is_control) {
        return Err(ProtocolValidationError::new(
            ValidationCode::OutOfRange,
            field,
            "value exceeds its length or character bound",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DesiredStateDocument, DesiredUser, DesiredXrayState, EndpointCandidate, EndpointMode,
        EndpointSource, NodeHeartbeat, NodeRuntimeState, RevisionProgress, RevisionResult,
        RevisionResultState,
    };
    use crate::crypto::Sha256Digest;
    use crate::error::ErrorCode;
    use crate::id::{
        ControllerInstanceId, CredentialId, EndpointId, NetworkId, NodeId, Revision,
        SequenceNumber, SigningKeyId, Timestamp, UserId,
    };
    use crate::secret::Secret;

    fn timestamp(value: &str) -> Timestamp {
        value.parse().unwrap()
    }

    fn result(state: RevisionResultState) -> RevisionResult {
        let config_digest = match state {
            RevisionResultState::Validated
            | RevisionResultState::Applied
            | RevisionResultState::RolledBack => Some(
                format!("sha256:{}", "a".repeat(64))
                    .parse::<Sha256Digest>()
                    .unwrap(),
            ),
            RevisionResultState::Received | RevisionResultState::Rejected => None,
        };
        let error_code = match state {
            RevisionResultState::Rejected | RevisionResultState::RolledBack => {
                Some(ErrorCode::ValidationFailed)
            }
            _ => None,
        };
        let rollback_revision =
            (state == RevisionResultState::RolledBack).then(|| Revision::new(4).unwrap());
        RevisionResult {
            state,
            config_digest,
            started_at: timestamp("2026-07-11T20:00:02Z"),
            completed_at: timestamp("2026-07-11T20:00:04Z"),
            error_code,
            rollback_revision,
        }
    }

    fn desired_document() -> DesiredStateDocument {
        DesiredStateDocument {
            schema_version: 1,
            network_id: NetworkId::new(),
            node_id: NodeId::new(),
            revision: Revision::new(1).unwrap(),
            created_at: timestamp("2026-07-11T20:00:00Z"),
            min_agent_version: "0.1.0".to_string(),
            users: vec![DesiredUser {
                user_id: UserId::new(),
                credential_id: CredentialId::new(),
                vless_uuid: Secret::new("2f55c837-7be6-4752-b58a-a7f51401bd89".to_string()),
                enabled: true,
            }],
            xray: DesiredXrayState {
                listen_port: 443,
                public_port: None,
                server_names: vec!["www.microsoft.com".to_string()],
                target: "www.microsoft.com:443".to_string(),
            },
            signing_key_id: SigningKeyId::new(),
            controller_instance_id: ControllerInstanceId::new(),
        }
    }

    fn heartbeat_with_candidate() -> NodeHeartbeat {
        let revision = Revision::new(7).unwrap();
        NodeHeartbeat {
            heartbeat_generation: SequenceNumber::new(1).unwrap(),
            agent_version: "0.1.0".to_string(),
            xray_version: Some("26.7.11".to_string()),
            state: NodeRuntimeState::Serving,
            revisions: RevisionProgress {
                desired_revision: Some(revision),
                received_revision: Some(revision),
                validated_revision: Some(revision),
                applied_revision: Some(revision),
            },
            provider_paused: false,
            endpoints: vec![EndpointCandidate {
                endpoint_id: EndpointId::new(),
                mode: EndpointMode::Direct,
                source: EndpointSource::Pcp,
                address: "1.1.1.1".to_string(),
                port: 44_321,
                applied_revision: revision,
                observed_at: timestamp("2026-07-11T20:00:00Z"),
                expires_at: Some(timestamp("2026-07-11T21:00:00Z")),
            }],
            telemetry_cursor: SequenceNumber::new(0).unwrap(),
        }
    }

    #[test]
    fn heartbeat_endpoints_are_unverified_revision_bound_candidates() {
        let heartbeat = heartbeat_with_candidate();
        assert!(heartbeat.validate().is_ok());
        let value = serde_json::to_value(&heartbeat).unwrap();
        assert!(value["endpoints"][0].get("status").is_none());
        assert_eq!(value["endpoints"][0]["source"], "pcp");
        let mut forged = value["endpoints"][0].clone();
        forged["status"] = serde_json::json!("verified");
        assert!(serde_json::from_value::<EndpointCandidate>(forged).is_err());

        let mut mismatched = heartbeat.clone();
        mismatched.endpoints[0].applied_revision = Revision::new(6).unwrap();
        assert!(mismatched.validate().is_err());

        let mut duplicate = heartbeat.clone();
        duplicate.endpoints.push(duplicate.endpoints[0].clone());
        assert!(duplicate.validate().is_err());

        let mut duplicate_address = heartbeat.clone();
        let mut second_identity = duplicate_address.endpoints[0].clone();
        second_identity.endpoint_id = EndpointId::new();
        duplicate_address.endpoints.push(second_identity);
        assert!(duplicate_address.validate().is_err());

        let mut invalid_source = heartbeat.clone();
        invalid_source.endpoints[0].source = EndpointSource::Relay;
        assert!(invalid_source.validate().is_err());

        let mut no_lease = heartbeat;
        no_lease.endpoints[0].expires_at = None;
        assert!(no_lease.validate().is_err());
    }

    #[test]
    fn heartbeat_generation_must_be_positive() {
        let mut heartbeat = heartbeat_with_candidate();
        heartbeat.heartbeat_generation = SequenceNumber::new(0).unwrap();
        assert!(heartbeat.validate().is_err());
    }

    #[test]
    fn revision_progress_requires_monotonic_lifecycle_cursors() {
        let progress = RevisionProgress {
            desired_revision: Some(Revision::new(12).unwrap()),
            received_revision: Some(Revision::new(12).unwrap()),
            validated_revision: Some(Revision::new(11).unwrap()),
            applied_revision: Some(Revision::new(10).unwrap()),
        };
        assert!(progress.validate().is_ok());

        let invalid = RevisionProgress {
            applied_revision: Some(Revision::new(12).unwrap()),
            ..progress
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn revision_result_transitions_are_monotonic_and_idempotent() {
        let received = result(RevisionResultState::Received);
        let validated = result(RevisionResultState::Validated);
        let applied = result(RevisionResultState::Applied);

        assert!(received.validate(Revision::new(5).unwrap()).is_ok());
        assert!(validated.validate_transition_from(Some(&received)).is_ok());
        assert!(applied.validate_transition_from(Some(&validated)).is_ok());
        assert!(applied.validate_transition_from(Some(&applied)).is_ok());
        assert!(received.validate_transition_from(Some(&validated)).is_err());
        assert!(validated.validate_transition_from(Some(&applied)).is_err());
    }

    #[test]
    fn terminal_state_payloads_are_validated() {
        let revision = Revision::new(5).unwrap();
        assert!(result(RevisionResultState::RolledBack)
            .validate(revision)
            .is_ok());

        let mut invalid = result(RevisionResultState::Applied);
        invalid.error_code = Some(ErrorCode::ValidationFailed);
        assert!(invalid.validate(revision).is_err());
    }

    #[test]
    fn desired_state_is_bound_to_exact_network_node_and_controller() {
        let document = desired_document();
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1],
            )
            .is_ok());
        assert!(document
            .validate_for(
                NetworkId::new(),
                document.node_id,
                document.controller_instance_id,
                None,
                &[1],
            )
            .is_err());
        assert!(document
            .validate_for(
                document.network_id,
                NodeId::new(),
                document.controller_instance_id,
                None,
                &[1],
            )
            .is_err());
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                ControllerInstanceId::new(),
                None,
                &[1],
            )
            .is_err());
    }

    #[test]
    fn desired_state_requires_canonical_vless_credentials_and_newer_revisions() {
        let mut document = desired_document();
        document.users[0].vless_uuid =
            Secret::new("2F55C837-7BE6-4752-B58A-A7F51401BD89".to_string());
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1],
            )
            .is_err());

        document.users[0].vless_uuid =
            Secret::new("2f55c837-7be6-4752-b58a-a7f51401bd89".to_string());
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                Some(document.revision),
                &[1],
            )
            .is_err());
    }

    #[test]
    fn desired_state_v2_requires_distinct_unprivileged_loopback_and_public_ports() {
        let mut document = desired_document();
        document.schema_version = 2;
        document.xray.listen_port = 10_443;
        document.xray.public_port = Some(443);
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1, 2],
            )
            .is_ok());

        document.xray.public_port = None;
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1, 2],
            )
            .is_err());
        document.xray.public_port = Some(10_443);
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1, 2],
            )
            .is_err());
        document.xray.public_port = Some(443);
        document.xray.listen_port = 443;
        assert!(document
            .validate_for(
                document.network_id,
                document.node_id,
                document.controller_instance_id,
                None,
                &[1, 2],
            )
            .is_err());
    }

    #[test]
    fn legacy_xray_wire_shape_rejects_an_explicit_null_public_port() {
        let value = serde_json::json!({
            "listenPort": 443,
            "publicPort": null,
            "serverNames": ["www.microsoft.com"],
            "target": "www.microsoft.com:443"
        });

        assert!(serde_json::from_value::<DesiredXrayState>(value).is_err());
    }
}
