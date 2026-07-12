use crate::{ManualEndpointInput, ManualEndpointStatus, ProviderPolicy, ProviderPolicyStatus};
use control_protocol::id::{NodeId, Revision, Timestamp};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Read as _;
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const SYSTEM_SETUP_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_SYSTEM_REQUEST_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SYSTEM_RESPONSE_BYTES: usize = 128 * 1024;
pub(crate) const PROVIDER_SETUP_FILE: &str = "provider-setup.json";
const MAX_PROVIDER_SETUP_BYTES: u64 = 4 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderSetupPreferences {
    pub schema_version: u16,
    pub relay_accepted: bool,
}

/// Reads the durable provider relay choice without exposing setup credentials.
///
/// # Errors
///
/// Returns an error when the owner-only preferences file is unsafe, oversized,
/// malformed, or uses an unsupported schema.
pub fn provider_relay_consent(data_dir: &Path) -> anyhow::Result<Option<bool>> {
    let path = data_dir.join(PROVIDER_SETUP_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("provider setup preferences path is unsafe");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let data_metadata = fs::symlink_metadata(data_dir)?;
        if data_metadata.file_type().is_symlink()
            || !data_metadata.is_dir()
            || metadata.uid() != data_metadata.uid()
            || metadata.gid() != data_metadata.gid()
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("provider setup preferences are not owner-only");
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_PROVIDER_SETUP_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || u64::try_from(bytes.len())? > MAX_PROVIDER_SETUP_BYTES {
        anyhow::bail!("provider setup preferences size is invalid");
    }
    let preferences: ProviderSetupPreferences = serde_json::from_slice(&bytes)?;
    if preferences.schema_version != 1 {
        anyhow::bail!("provider setup preferences schema is unsupported");
    }
    Ok(Some(preferences.relay_accepted))
}

/// A setup invitation that can be serialized only onto the authenticated local
/// transport and can never reveal its contents through formatting.
pub struct SetupInvitation(Zeroizing<String>);

impl SetupInvitation {
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SetupInvitation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted setup invitation]")
    }
}

impl Serialize for SetupInvitation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SetupInvitation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 32 * 1024 {
            value.zeroize();
            return Err(serde::de::Error::custom(
                "setup invitation length is invalid",
            ));
        }
        Ok(Self::new(value))
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSetupRequest {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub operation: SystemSetupOperation,
}

impl SystemSetupRequest {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == SYSTEM_SETUP_SCHEMA_VERSION,
            "unsupported system setup protocol version"
        );
        anyhow::ensure!(!self.request_id.is_nil(), "request ID cannot be nil");
        match &self.operation {
            SystemSetupOperation::ConfirmSetup {
                setup_invitation,
                provider_policy,
                ..
            } => {
                provider_policy.validate()?;
                anyhow::ensure!(
                    !setup_invitation.expose().is_empty()
                        && setup_invitation.expose().len() <= 32 * 1024,
                    "setup invitation length is invalid"
                );
            }
            SystemSetupOperation::UpdateProviderPolicy { provider_policy } => {
                provider_policy.validate()?;
            }
            SystemSetupOperation::Status {}
            | SystemSetupOperation::Pause {}
            | SystemSetupOperation::Resume {}
            | SystemSetupOperation::ConfigureManualEndpoint { .. }
            | SystemSetupOperation::ClearManualEndpoint {}
            | SystemSetupOperation::Unpair { .. } => {}
        }
        Ok(())
    }

    #[must_use]
    pub const fn method_name(&self) -> &'static str {
        match self.operation {
            SystemSetupOperation::Status {} => "status",
            SystemSetupOperation::ConfirmSetup { .. } => "confirmSetup",
            SystemSetupOperation::UpdateProviderPolicy { .. } => "updateProviderPolicy",
            SystemSetupOperation::Pause {} => "pause",
            SystemSetupOperation::Resume {} => "resume",
            SystemSetupOperation::ConfigureManualEndpoint { .. } => "configureManualEndpoint",
            SystemSetupOperation::ClearManualEndpoint {} => "clearManualEndpoint",
            SystemSetupOperation::Unpair { .. } => "unpair",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "camelCase", deny_unknown_fields)]
pub enum SystemSetupOperation {
    Status {},
    ConfirmSetup {
        setup_invitation: SetupInvitation,
        accept_host_owner: bool,
        accept_exit_ip: bool,
        accept_router_mapping: bool,
        accept_relay: bool,
        provider_policy: ProviderPolicy,
    },
    UpdateProviderPolicy {
        provider_policy: ProviderPolicy,
    },
    Pause {},
    Resume {},
    ConfigureManualEndpoint {
        endpoint: ManualEndpointInput,
    },
    ClearManualEndpoint {},
    Unpair {
        confirm_node_id: NodeId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSetupResponse {
    pub schema_version: u16,
    pub request_id: Uuid,
    pub outcome: SystemSetupOutcome,
}

impl SystemSetupResponse {
    #[must_use]
    pub fn success(request_id: Uuid, result: SystemSetupResult) -> Self {
        Self {
            schema_version: SYSTEM_SETUP_SCHEMA_VERSION,
            request_id,
            outcome: SystemSetupOutcome::Success {
                result: Box::new(result),
            },
        }
    }

    #[must_use]
    pub fn error(request_id: Uuid, code: SystemSetupErrorCode, retryable: bool) -> Self {
        Self {
            schema_version: SYSTEM_SETUP_SCHEMA_VERSION,
            request_id,
            outcome: SystemSetupOutcome::Error {
                error: SystemSetupError { code, retryable },
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum SystemSetupOutcome {
    Success { result: Box<SystemSetupResult> },
    Error { error: SystemSetupError },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum SystemSetupResult {
    Status { status: SystemServiceStatus },
    SetupComplete { status: SystemServiceStatus },
    ProviderPolicyUpdated { status: ProviderPolicyStatus },
    ManualEndpointUpdated { status: ManualEndpointStatus },
    ManualEndpointCleared {},
    Unpaired { status: SystemServiceStatus },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SystemSetupErrorCode {
    UnauthorizedPeer,
    InvalidRequest,
    DuplicateRequestInProgress,
    PackageVerificationFailed,
    SetupFailed,
    NotEnrolled,
    ConfirmationMismatch,
    StateUnavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSetupError {
    pub code: SystemSetupErrorCode,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SystemServicePhase {
    Unpaired,
    Enrolled,
    Ready,
    NeedsAttention,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemServiceStatus {
    pub phase: SystemServicePhase,
    pub package_verified: bool,
    pub node_id: Option<NodeId>,
    pub applied_revision: Option<Revision>,
    pub last_sync_at: Option<Timestamp>,
    pub provider_policy: Option<ProviderPolicyStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_schema_is_closed_and_secret_debug_is_redacted() {
        let secret = SetupInvitation::new("pnnode1_secret".to_string());
        assert_eq!(format!("{secret:?}"), "[redacted setup invitation]");
        let request = format!(
            r#"{{"schemaVersion":1,"requestId":"{}","operation":{{"method":"pause","extra":true}}}}"#,
            Uuid::new_v4()
        );
        assert!(serde_json::from_str::<SystemSetupRequest>(&request).is_err());
        let valid = SystemSetupRequest {
            schema_version: 1,
            request_id: Uuid::new_v4(),
            operation: SystemSetupOperation::Pause {},
        };
        let serialized = serde_json::to_vec(&valid).unwrap();
        let decoded: SystemSetupRequest = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(decoded.method_name(), "pause");
    }

    #[test]
    fn response_never_accepts_unknown_fields() {
        let response = format!(
            r#"{{"schemaVersion":1,"requestId":"{}","outcome":{{"status":"error","error":{{"code":"invalidRequest","retryable":false,"detail":"secret"}}}}}}"#,
            Uuid::new_v4()
        );
        assert!(serde_json::from_str::<SystemSetupResponse>(&response).is_err());
    }

    #[test]
    fn relay_consent_reader_is_strict_and_never_needs_invitation_material() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(provider_relay_consent(directory.path()).unwrap(), None);
        let path = directory.path().join(PROVIDER_SETUP_FILE);
        fs::write(&path, r#"{"schemaVersion":1,"relayAccepted":true}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            provider_relay_consent(directory.path()).unwrap(),
            Some(true)
        );
        fs::write(
            &path,
            r#"{"schemaVersion":1,"relayAccepted":true,"secret":"bad"}"#,
        )
        .unwrap();
        assert!(provider_relay_consent(directory.path()).is_err());
    }
}
