//! Member account, device session, and signed profile-bundle contracts.

use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest, X25519PublicKey};
use crate::id::{
    AssignmentId, BundleGeneration, BundleId, ControllerInstanceId, CredentialId,
    DeviceActivationId, DeviceId, NetworkId, NodeId, SessionId, SigningKeyId, Timestamp, UserId,
};
use crate::node::EndpointMode;
use crate::secret::Secret;
use crate::validation::{ProtocolValidationError, ValidationCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Stable account lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountStatus {
    /// Account may refresh and use assigned nodes.
    Active,
    /// Refresh is blocked and node credential removal is pending or complete.
    Disabled,
    /// Account is tombstoned and cannot authenticate.
    Deleted,
}

/// Safe member metadata returned to its enrolled devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountMetadata {
    /// Stable logical member identity.
    pub user_id: UserId,
    /// Mutable presentation name.
    pub display_name: String,
    /// Current account lifecycle state.
    pub status: AccountStatus,
}

/// Administrator request to create one logical member account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAccountRequest {
    /// Mutable presentation name; never an authentication identity.
    pub display_name: String,
}

impl CreateAccountRequest {
    /// Validates bounded account metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the display name is empty, too long, or contains
    /// control characters.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_text(&self.display_name, 128, "displayName")
    }
}

/// Administrator request to change a member lifecycle explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetAccountStatusRequest {
    /// Requested account status; deleting is terminal at Control.
    pub status: AccountStatus,
}

/// Lifecycle of one logical account-to-node assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountNodeAssignmentStatus {
    /// The account should be present in this node's desired state.
    Enabled,
    /// The assignment is retained but excluded from desired state.
    Disabled,
    /// The assignment is tombstoned and cannot be re-enabled.
    Deleted,
}

/// Safe administrator-facing account-to-node assignment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountNodeAssignment {
    /// Stable assignment identity.
    pub assignment_id: AssignmentId,
    /// Assigned node identity.
    pub node_id: NodeId,
    /// Current assignment lifecycle.
    pub status: AccountNodeAssignmentStatus,
}

/// Complete safe administrator view of one member and its node set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSummary {
    /// Safe logical account metadata.
    pub account: AccountMetadata,
    /// Complete assignments sorted by node identity.
    pub assignments: Vec<AccountNodeAssignment>,
    /// Account creation time.
    pub created_at: Timestamp,
    /// Last lifecycle or assignment update time.
    pub updated_at: Timestamp,
}

/// Administrator request that atomically replaces an account's enabled nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceAccountNodesRequest {
    /// Complete desired node set; omission disables an existing assignment.
    pub node_ids: Vec<NodeId>,
}

impl ReplaceAccountNodesRequest {
    /// Validates a bounded duplicate-free node set.
    ///
    /// # Errors
    ///
    /// Returns an error when more than 100 nodes are requested or a node ID is
    /// repeated.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.node_ids.len() > 100 {
            return Err(ProtocolValidationError::new(
                ValidationCode::OutOfRange,
                "nodeIds",
                "an account may be assigned to at most 100 nodes",
            ));
        }
        if self.node_ids.iter().copied().collect::<HashSet<_>>().len() != self.node_ids.len() {
            return Err(ProtocolValidationError::new(
                ValidationCode::DuplicateIdentity,
                "nodeIds",
                "node IDs must be unique",
            ));
        }
        Ok(())
    }
}

/// Asymmetric identity and proof generated locally for a member device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceEnrollment {
    /// User-visible device name.
    pub display_name: String,
    /// Connect semantic version.
    pub client_version: String,
    /// Platform identifier such as `windows-x64`.
    pub platform: String,
    /// Locally generated Ed25519 request-signing key.
    pub identity_public_key: Ed25519PublicKey,
    /// Locally generated X25519 bundle-recipient key.
    pub encryption_public_key: X25519PublicKey,
    /// Fresh enrollment nonce.
    pub nonce: Nonce,
    /// Signature over the complete activation or login transcript.
    pub proof: Ed25519Signature,
}

impl DeviceEnrollment {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_text(&self.display_name, 128, "device.displayName")?;
        validate_text(&self.client_version, 64, "device.clientVersion")?;
        validate_text(&self.platform, 64, "device.platform")
    }
}

/// Request that consumes a one-time member-device activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumeDeviceActivationRequest {
    /// High-entropy single-use activation secret.
    pub activation_secret: Secret<String>,
    /// Locally generated device identity.
    pub device: DeviceEnrollment,
}

impl ConsumeDeviceActivationRequest {
    /// Validates bounded activation fields before proof verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the activation secret is empty or device metadata
    /// violates its protocol bounds.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.activation_secret.expose_secret().is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "activationSecret",
                "activation secret is required",
            ));
        }
        self.device.validate()
    }
}

/// Optional password login request that still creates a device-scoped session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSessionRequest {
    /// Operator-configured account identifier; failures remain non-enumerating.
    pub account: String,
    /// Write-only password credential.
    pub password: Secret<String>,
    /// Locally generated device identity bound to the session.
    pub device: DeviceEnrollment,
}

impl CreateSessionRequest {
    /// Validates bounded login fields before authentication and proof checks.
    ///
    /// # Errors
    ///
    /// Returns an error when account or device metadata is invalid or a required
    /// password is empty.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_text(&self.account, 254, "account")?;
        if self.password.expose_secret().is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "password",
                "password is required",
            ));
        }
        self.device.validate()
    }
}

/// Short-lived access and rotating refresh credentials shown only at issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCredentials {
    /// Session rotation-family identity.
    pub session_id: SessionId,
    /// In-memory bearer credential.
    pub access_token: Secret<String>,
    /// Access-token expiry, at most 15 minutes after issuance.
    pub access_expires_at: Timestamp,
    /// Device-scoped rotating credential stored in the OS credential store.
    pub refresh_credential: Secret<String>,
    /// Refresh expiry, at most 30 days after issuance.
    pub refresh_expires_at: Timestamp,
}

impl SessionCredentials {
    /// Validates token presence and expiry ordering.
    ///
    /// # Errors
    ///
    /// Returns an error when either credential is empty or the refresh
    /// credential does not outlive the access token.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.access_token.expose_secret().is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "accessToken",
                "access token is required",
            ));
        }
        if self.refresh_credential.expose_secret().is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "refreshCredential",
                "refresh credential is required",
            ));
        }
        if self.refresh_expires_at <= self.access_expires_at {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "refreshExpiresAt",
                "refresh credential must outlive the access token",
            ));
        }
        Ok(())
    }
}

/// Response to device activation or password login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDeviceSessionResponse {
    /// Consumed activation record, when activation created the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_id: Option<DeviceActivationId>,
    /// Account metadata safe for display.
    pub account: AccountMetadata,
    /// Independently revocable device identity.
    pub device_id: DeviceId,
    /// Newly issued credentials.
    pub credentials: SessionCredentials,
}

/// Request to rotate a device-scoped refresh credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefreshSessionRequest {
    /// Current refresh credential; the credential identifies its session family.
    pub refresh_credential: Secret<String>,
}

/// Response containing a rotated credential pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshSessionResponse {
    /// Current safe account metadata.
    pub account: AccountMetadata,
    /// Replacement credentials; the old refresh value is invalidated atomically.
    pub credentials: SessionCredentials,
}

/// Lifecycle state of one independently revocable member-device session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceSessionStatus {
    /// Refresh is permitted.
    Active,
    /// Session was explicitly logged out or administratively revoked.
    Revoked,
    /// Session passed its hard refresh expiry.
    Expired,
}

/// Safe device-session metadata for account and administrator views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSession {
    /// Rotation-family identity.
    pub session_id: SessionId,
    /// Owning member device.
    pub device_id: DeviceId,
    /// Current lifecycle state.
    pub status: DeviceSessionStatus,
    /// Session creation time.
    pub created_at: Timestamp,
    /// Last controller-observed use.
    pub last_seen_at: Timestamp,
    /// Hard refresh expiry.
    pub expires_at: Timestamp,
}

/// Signed manifest descriptor for one encrypted node profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDescriptor {
    /// Stable node identity.
    pub node_id: NodeId,
    /// Safe presentation name.
    pub display_name: String,
    /// Optional safe region label.
    pub region: Option<String>,
    /// Direct or relay endpoint mode.
    pub endpoint_mode: EndpointMode,
    /// Digest of the encrypted profile payload.
    pub encrypted_payload_digest: Sha256Digest,
    /// Lower values are preferred when other health inputs are equivalent.
    pub priority: u16,
}

/// Safe signed selection policy hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectionHints {
    /// Minimum time to retain a healthy automatic selection.
    pub minimum_hold_seconds: u32,
    /// Latency improvement required before switching healthy nodes.
    pub latency_tolerance_milliseconds: u32,
    /// Consecutive failures required before fallback.
    pub failure_threshold: u16,
}

/// Explicit replacement or revocation metadata carried by a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BundleReplacement {
    /// Previous bundle superseded by this generation.
    pub replaces_bundle_id: BundleId,
    /// Safe reason code such as `credential_rotation`.
    pub reason: String,
}

/// Canonical signed profile-bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileBundleManifest {
    /// Envelope schema version.
    pub schema_version: u16,
    /// Decrypted payload format version.
    pub format_version: u16,
    /// Immutable bundle identity.
    pub bundle_id: BundleId,
    /// Bound private network.
    pub network_id: NetworkId,
    /// Bound logical account.
    pub user_id: UserId,
    /// Exact recipient device.
    pub device_id: DeviceId,
    /// Public signing-key identity.
    pub signing_key_id: SigningKeyId,
    /// Controller epoch used for rollback protection.
    pub controller_instance_id: ControllerInstanceId,
    /// Monotonic per-device generation.
    pub generation: BundleGeneration,
    /// Controller issue time.
    pub issued_at: Timestamp,
    /// Earliest permitted use.
    pub not_before: Timestamp,
    /// Recommended online refresh time.
    pub refresh_after: Timestamp,
    /// Hard deadline for cached offline use.
    pub offline_expires_at: Timestamp,
    /// Minimum supported Connect semantic version.
    pub min_client_version: String,
    /// Signed current account status.
    pub account_status: AccountStatus,
    /// Complete permitted node set; absence means removal.
    pub profiles: Vec<ProfileDescriptor>,
    /// Safe selection policy hints.
    pub selection_hints: SelectionHints,
    /// Optional replacement metadata.
    pub replacement: Option<BundleReplacement>,
}

/// Standard recipient-encryption construction for profile payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileEncryptionAlgorithm {
    /// HPKE base mode with X25519, HKDF-SHA256, and ChaCha20-Poly1305.
    HpkeBaseX25519HkdfSha256ChaCha20Poly1305,
}

/// One profile encrypted to the enrolled device's X25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedProfilePayload {
    /// Node whose complete profile is encrypted.
    pub node_id: NodeId,
    /// Reviewed recipient-encryption construction.
    pub algorithm: ProfileEncryptionAlgorithm,
    /// Sender ephemeral X25519 public key.
    pub ephemeral_public_key: X25519PublicKey,
    /// Algorithm nonce encoded as unpadded base64url.
    pub nonce: Nonce,
    /// Authenticated ciphertext, deliberately redacted from diagnostics.
    pub ciphertext: Secret<String>,
}

/// Signed and per-device encrypted profile-bundle envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedProfileBundle {
    /// Canonical signed metadata and encrypted-payload digests.
    pub manifest: ProfileBundleManifest,
    /// Complete encrypted profile set.
    pub encrypted_profiles: Vec<EncryptedProfilePayload>,
    /// Signature over the canonical manifest and payload digests.
    pub signature: Ed25519Signature,
}

impl SignedProfileBundle {
    /// Validates schema, time bounds, and complete unique node-set shape.
    ///
    /// This does not verify the signature, digest bytes, or ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, inconsistent time bounds,
    /// duplicate or mismatched node sets, invalid display metadata, or empty
    /// ciphertext.
    pub fn validate_shape(
        &self,
        supported_schema_versions: &[u16],
        supported_format_versions: &[u16],
    ) -> Result<(), ProtocolValidationError> {
        let manifest = &self.manifest;
        if !supported_schema_versions.contains(&manifest.schema_version) {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "manifest.schemaVersion",
                "profile-bundle schema version is not supported",
            ));
        }
        if !supported_format_versions.contains(&manifest.format_version) {
            return Err(ProtocolValidationError::new(
                ValidationCode::UnsupportedSchema,
                "manifest.formatVersion",
                "profile payload format version is not supported",
            ));
        }
        validate_text(
            &manifest.min_client_version,
            64,
            "manifest.minClientVersion",
        )?;
        if manifest.issued_at > manifest.refresh_after
            || manifest.not_before > manifest.offline_expires_at
            || manifest.refresh_after >= manifest.offline_expires_at
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "manifest.offlineExpiresAt",
                "bundle issue, refresh, and offline deadlines are inconsistent",
            ));
        }
        if manifest.profiles.len() > 1_000
            || manifest.profiles.len() != self.encrypted_profiles.len()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "encryptedProfiles",
                "encrypted profiles must exactly match the manifest profile count",
            ));
        }
        let mut manifest_nodes = HashSet::with_capacity(manifest.profiles.len());
        for profile in &manifest.profiles {
            if !manifest_nodes.insert(profile.node_id) {
                return Err(ProtocolValidationError::new(
                    ValidationCode::DuplicateIdentity,
                    "manifest.profiles",
                    "manifest node IDs must be unique",
                ));
            }
            validate_text(&profile.display_name, 128, "manifest.profiles.displayName")?;
            if let Some(region) = &profile.region {
                validate_text(region, 64, "manifest.profiles.region")?;
            }
        }
        let mut payload_nodes = HashSet::with_capacity(self.encrypted_profiles.len());
        for profile in &self.encrypted_profiles {
            if profile.ciphertext.expose_secret().is_empty() {
                return Err(ProtocolValidationError::new(
                    ValidationCode::MissingField,
                    "encryptedProfiles.ciphertext",
                    "encrypted profile ciphertext is required",
                ));
            }
            if !payload_nodes.insert(profile.node_id) {
                return Err(ProtocolValidationError::new(
                    ValidationCode::DuplicateIdentity,
                    "encryptedProfiles",
                    "encrypted profile node IDs must be unique",
                ));
            }
        }
        if manifest_nodes != payload_nodes {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "encryptedProfiles",
                "encrypted profile node set must exactly match the manifest",
            ));
        }
        Ok(())
    }
}

/// Decrypted, device-bound payload corresponding to a signed bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileBundlePayload {
    /// Immutable bundle identity copied from the manifest.
    pub bundle_id: BundleId,
    /// Exact recipient device copied from the manifest.
    pub device_id: DeviceId,
    /// Generation copied from the manifest.
    pub generation: BundleGeneration,
    /// Complete decrypted node profile set.
    pub profiles: Vec<NodeProfile>,
}

impl ProfileBundlePayload {
    /// Validates manifest binding and the complete decrypted node set.
    ///
    /// # Errors
    ///
    /// Returns an error when bundle, device, or generation binding differs;
    /// when node sets are incomplete or duplicated; or when a node profile is
    /// structurally invalid.
    pub fn validate_against(
        &self,
        manifest: &ProfileBundleManifest,
    ) -> Result<(), ProtocolValidationError> {
        if self.bundle_id != manifest.bundle_id
            || self.device_id != manifest.device_id
            || self.generation != manifest.generation
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "profilePayload",
                "decrypted payload is not bound to the signed manifest",
            ));
        }
        if self.profiles.len() != manifest.profiles.len() {
            return Err(ProtocolValidationError::new(
                ValidationCode::InconsistentState,
                "profilePayload.profiles",
                "decrypted profiles must exactly match the manifest count",
            ));
        }
        let manifest_nodes: HashSet<_> =
            manifest.profiles.iter().map(|item| item.node_id).collect();
        let mut payload_nodes = HashSet::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            profile.validate()?;
            if !payload_nodes.insert(profile.node_id) {
                return Err(ProtocolValidationError::new(
                    ValidationCode::DuplicateIdentity,
                    "profilePayload.profiles",
                    "decrypted profile node IDs must be unique",
                ));
            }
        }
        if manifest_nodes != payload_nodes {
            return Err(ProtocolValidationError::new(
                ValidationCode::IdentityMismatch,
                "profilePayload.profiles",
                "decrypted node set must exactly match the signed manifest",
            ));
        }
        Ok(())
    }
}

/// Verified endpoint carried inside a member node profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileEndpoint {
    /// Direct or relay path fixed by the signed bundle.
    pub mode: EndpointMode,
    /// Verified hostname or IP address.
    pub address: String,
    /// Verified TCP port.
    pub port: u16,
}

/// VLESS and REALITY parameters needed by the normalized Connect profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RealityConnectionParameters {
    /// Per-node VLESS bearer credential.
    pub vless_uuid: Secret<String>,
    /// Supported VLESS flow such as `xtls-rprx-vision`.
    pub flow: String,
    /// REALITY server name.
    pub server_name: String,
    /// Supported client fingerprint.
    pub fingerprint: String,
    /// Node-owned REALITY public key, redacted from ordinary diagnostics.
    pub reality_public_key: Secret<String>,
    /// REALITY short ID, redacted from ordinary diagnostics.
    pub short_id: Secret<String>,
    /// REALITY spider path, redacted from ordinary diagnostics.
    pub spider_x: Secret<String>,
}

/// One complete decrypted node profile for an enrolled member device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeProfile {
    /// Stable node identity.
    pub node_id: NodeId,
    /// Stable per-user, per-node credential identity.
    pub credential_id: CredentialId,
    /// Safe presentation name.
    pub display_name: String,
    /// Optional safe region label.
    pub region: Option<String>,
    /// Externally verified direct or relay endpoint.
    pub endpoint: ProfileEndpoint,
    /// Secret-bearing VLESS and REALITY connection parameters.
    pub connection: RealityConnectionParameters,
}

impl NodeProfile {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_text(&self.display_name, 128, "profiles.displayName")?;
        if let Some(region) = &self.region {
            validate_text(region, 64, "profiles.region")?;
        }
        validate_text(&self.endpoint.address, 253, "profiles.endpoint.address")?;
        if self.endpoint.address.contains('/')
            || self.endpoint.address.contains(char::is_whitespace)
            || self.endpoint.port == 0
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidFormat,
                "profiles.endpoint",
                "profile endpoint must be a hostname or IP with a non-zero port",
            ));
        }
        validate_text(&self.connection.flow, 64, "profiles.connection.flow")?;
        validate_text(
            &self.connection.server_name,
            253,
            "profiles.connection.serverName",
        )?;
        validate_text(
            &self.connection.fingerprint,
            32,
            "profiles.connection.fingerprint",
        )?;
        if self.connection.vless_uuid.expose_secret().is_empty()
            || self
                .connection
                .reality_public_key
                .expose_secret()
                .is_empty()
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "profiles.connection",
                "VLESS and REALITY connection credentials are required",
            ));
        }
        Ok(())
    }
}

fn validate_text(
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
        CreateAccountRequest, CreateSessionRequest, DeviceEnrollment, ReplaceAccountNodesRequest,
    };
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, X25519PublicKey};
    use crate::secret::Secret;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    fn enrollment() -> DeviceEnrollment {
        DeviceEnrollment {
            display_name: "Work laptop".to_string(),
            client_version: "0.1.0".to_string(),
            platform: "macos-arm64".to_string(),
            identity_public_key: URL_SAFE_NO_PAD
                .encode([1_u8; 32])
                .parse::<Ed25519PublicKey>()
                .unwrap(),
            encryption_public_key: URL_SAFE_NO_PAD
                .encode([2_u8; 32])
                .parse::<X25519PublicKey>()
                .unwrap(),
            nonce: URL_SAFE_NO_PAD.encode([3_u8; 16]).parse::<Nonce>().unwrap(),
            proof: URL_SAFE_NO_PAD
                .encode([4_u8; 64])
                .parse::<Ed25519Signature>()
                .unwrap(),
        }
    }

    #[test]
    fn nested_session_debug_output_redacts_credentials() {
        let request = CreateSessionRequest {
            account: "member@example.test".to_string(),
            password: Secret::new("do-not-log-this".to_string()),
            device: enrollment(),
        };
        let debug = format!("{request:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("do-not-log-this"));
        assert!(request.validate().is_ok());
    }

    #[test]
    fn member_dtos_use_camel_case_and_secret_wire_values() {
        let request = CreateSessionRequest {
            account: "member@example.test".to_string(),
            password: Secret::new("wire-secret".to_string()),
            device: enrollment(),
        };
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["password"], "wire-secret");
        assert!(value["device"].get("identityPublicKey").is_some());
        assert!(value["device"].get("encryptionPublicKey").is_some());
    }

    #[test]
    fn administrator_account_inputs_are_bounded_and_duplicate_free() {
        assert!(CreateAccountRequest {
            display_name: "Friend".to_string(),
        }
        .validate()
        .is_ok());
        assert!(CreateAccountRequest {
            display_name: String::new(),
        }
        .validate()
        .is_err());

        let node_id = crate::id::NodeId::new();
        assert!(ReplaceAccountNodesRequest {
            node_ids: vec![node_id, node_id],
        }
        .validate()
        .is_err());
    }
}
