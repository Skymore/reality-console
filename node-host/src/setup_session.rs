use crate::{
    bootstrap_and_install_user_service, inspect_setup_code, BootstrapRequest,
    BootstrapServiceOutcome, EnrollmentState, NodeSetupPreview, UserServiceInstallRequest,
};
use anyhow::{bail, Context as _, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_PENDING_SETUP_SESSIONS: usize = 8;

/// Secret-free handle returned to a Node Host renderer after link ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSetupSession {
    /// Random process-local handle; it is not an enrollment credential.
    pub session_id: Uuid,
    /// Safe confirmation details with no invitation ID or bearer material.
    pub preview: NodeSetupPreview,
}

/// Installer-owned inputs combined with renderer-approved provider choices.
///
/// This type intentionally has no serde implementation. A desktop backend
/// resolves package paths and hashes itself, then combines only the three
/// explicit provider choices before confirmation.
pub struct NodeSetupInstallRequest {
    data_dir: PathBuf,
    xray_binary_path: PathBuf,
    xray_sha256: String,
    agent_binary_path: PathBuf,
    accept_host_owner: bool,
    accept_exit_ip: bool,
    accept_router_mapping: bool,
}

impl NodeSetupInstallRequest {
    /// Constructs package-owned setup input inside the trusted desktop backend.
    #[must_use]
    pub fn new(
        data_dir: PathBuf,
        xray_binary_path: PathBuf,
        xray_sha256: String,
        agent_binary_path: PathBuf,
        accept_host_owner: bool,
        accept_exit_ip: bool,
        accept_router_mapping: bool,
    ) -> Self {
        Self {
            data_dir,
            xray_binary_path,
            xray_sha256,
            agent_binary_path,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        }
    }
}

struct PendingSetup {
    input: Zeroizing<String>,
    preview: NodeSetupPreview,
}

/// Checked-out setup material owned by a trusted desktop backend while a
/// privileged local request is in flight.
///
/// This value has no serialization implementation and redacts formatting. Its
/// invitation is zeroized when dropped or returned to the session store.
pub struct PendingNodeSetup {
    input: Zeroizing<String>,
    preview: NodeSetupPreview,
}

impl PendingNodeSetup {
    #[must_use]
    pub fn setup_invitation(&self) -> &str {
        &self.input
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.preview.expires_at.as_datetime() <= OffsetDateTime::now_utc()
    }
}

impl fmt::Debug for PendingNodeSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingNodeSetup")
            .field("input", &"[redacted]")
            .field("preview", &self.preview)
            .finish()
    }
}

/// Process-local owner of pending Node Host setup bearer material.
///
/// A desktop backend ingests a code/link here before invoking renderer UI. The
/// renderer receives only [`NodeSetupSession`], then confirms by random session
/// ID. Codes are removed after success and retained only for a bounded retry
/// after failure.
pub struct NodeSetupSessionStore {
    sessions: Mutex<BTreeMap<Uuid, PendingSetup>>,
}

impl Default for NodeSetupSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeSetupSessionStore {
    /// Creates an empty process-local setup store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    /// Ingests one pasted or deep-linked setup value and returns a safe preview.
    ///
    /// # Errors
    ///
    /// Returns an error when input is malformed, expired, or the bounded
    /// process-local queue is full.
    pub fn begin(&self, input: &str) -> Result<NodeSetupSession> {
        let input = input.trim();
        let preview = inspect_setup_code(input)?;
        if preview.expires_at.as_datetime() <= OffsetDateTime::now_utc() {
            bail!("Node Host setup invitation has expired");
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?;
        sessions.retain(|_, pending| {
            pending.preview.expires_at.as_datetime() > OffsetDateTime::now_utc()
        });
        if sessions.len() >= MAX_PENDING_SETUP_SESSIONS {
            bail!("too many Node Host setup sessions are pending");
        }
        let session_id = Uuid::new_v4();
        sessions.insert(
            session_id,
            PendingSetup {
                input: Zeroizing::new(input.to_string()),
                preview: preview.clone(),
            },
        );
        Ok(NodeSetupSession {
            session_id,
            preview,
        })
    }

    /// Cancels a pending setup and immediately zeroizes its bearer input.
    ///
    /// # Errors
    ///
    /// Returns an error only when the process-local session lock is unavailable.
    pub fn cancel(&self, session_id: Uuid) -> Result<bool> {
        let removed = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?
            .remove(&session_id)
            .is_some();
        Ok(removed)
    }

    /// Removes a pending invitation from the store for one privileged IPC
    /// attempt. The renderer can provide only the random session ID.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is missing, expired, or already in
    /// progress.
    pub fn checkout(&self, session_id: Uuid) -> Result<PendingNodeSetup> {
        let pending = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?
            .remove(&session_id)
            .context("Node Host setup session is missing or already in progress")?;
        if pending.preview.expires_at.as_datetime() <= OffsetDateTime::now_utc() {
            bail!("Node Host setup invitation has expired");
        }
        Ok(PendingNodeSetup {
            input: pending.input,
            preview: pending.preview,
        })
    }

    /// Restores checked-out setup material after a retryable IPC or setup
    /// failure. Expired material is dropped and zeroized instead.
    ///
    /// # Errors
    ///
    /// Returns an error when the session store is unavailable or the same
    /// session ID has already been restored.
    pub fn restore(&self, session_id: Uuid, pending: PendingNodeSetup) -> Result<bool> {
        if pending.is_expired() {
            return Ok(false);
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?;
        if sessions.contains_key(&session_id) {
            bail!("Node Host setup session is already pending");
        }
        sessions.insert(
            session_id,
            PendingSetup {
                input: pending.input,
                preview: pending.preview,
            },
        );
        Ok(true)
    }

    /// Confirms a pending setup and installs the current-user background service.
    ///
    /// Xray and agent paths plus the Xray digest must come from the signed
    /// package backend, never renderer input. A failed operation restores the
    /// still-valid in-memory session so one `Try again` action is safe.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/expired session, invalid installer
    /// inputs, enrollment failure, or background-service registration failure.
    pub async fn confirm_and_install(
        &self,
        session_id: Uuid,
        install: NodeSetupInstallRequest,
    ) -> Result<BootstrapServiceOutcome> {
        let NodeSetupInstallRequest {
            data_dir,
            xray_binary_path,
            xray_sha256,
            agent_binary_path,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        } = install;
        let pending = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?;
            sessions
                .remove(&session_id)
                .context("Node Host setup session is missing or already in progress")?
        };
        let enrollment_already_exists = crate::status(&data_dir)
            .is_ok_and(|status| status.enrollment_state == EnrollmentState::Enrolled);
        if pending.preview.expires_at.as_datetime() <= OffsetDateTime::now_utc()
            && !enrollment_already_exists
        {
            bail!("Node Host setup invitation has expired");
        }
        let request = BootstrapRequest::from_setup_code(
            &pending.input,
            xray_binary_path,
            xray_sha256,
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        )?;
        let result = bootstrap_and_install_user_service(
            &data_dir,
            request,
            &UserServiceInstallRequest::new(agent_binary_path),
        )
        .await;
        let enrollment_exists = enrollment_already_exists
            || crate::status(&data_dir)
                .is_ok_and(|status| status.enrollment_state == EnrollmentState::Enrolled);
        if result.is_err()
            && (enrollment_exists
                || pending.preview.expires_at.as_datetime() > OffsetDateTime::now_utc())
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow::anyhow!("Node Host setup session lock is unavailable"))?;
            sessions.insert(session_id, pending);
        }
        result
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::NodeSetupSessionStore;
    use control_protocol::crypto::Sha256Digest;
    use control_protocol::id::{NodeInvitationId, Timestamp};
    use control_protocol::node::{
        encode_node_setup_code, CreateNodeInvitationResponse, PairingPurpose,
    };
    use control_protocol::secret::Secret;
    use time::{Duration, OffsetDateTime};

    #[test]
    fn renderer_session_is_bounded_and_never_contains_the_bearer_secret() {
        let invitation = CreateNodeInvitationResponse {
            invitation_id: NodeInvitationId::new(),
            purpose: PairingPurpose::NodeEnrollment,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::minutes(5)),
            invitation_secret: Secret::new(
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY".to_string(),
            ),
            controller_origin: "https://control.example.test".to_string(),
            controller_fingerprint: format!("sha256:{}", "a".repeat(64))
                .parse::<Sha256Digest>()
                .unwrap(),
        };
        let code = encode_node_setup_code("Friend node", &invitation).unwrap();
        let store = NodeSetupSessionStore::new();
        let session = store.begin(code.expose_secret()).unwrap();

        let serialized = serde_json::to_string(&session).unwrap();
        assert!(!serialized.contains(code.expose_secret()));
        assert!(!serialized.contains(invitation.invitation_secret.expose_secret()));
        assert_eq!(session.preview.display_name, "Friend node");
        assert_eq!(store.pending_count(), 1);
        assert!(store.cancel(session.session_id).unwrap());
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn privileged_checkout_is_retry_safe_and_redacts_debug_output() {
        let invitation = CreateNodeInvitationResponse {
            invitation_id: NodeInvitationId::new(),
            purpose: PairingPurpose::NodeEnrollment,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::minutes(5)),
            invitation_secret: Secret::new(
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY".to_string(),
            ),
            controller_origin: "https://control.example.test".to_string(),
            controller_fingerprint: format!("sha256:{}", "a".repeat(64))
                .parse::<Sha256Digest>()
                .unwrap(),
        };
        let code = encode_node_setup_code("Retry node", &invitation).unwrap();
        let store = NodeSetupSessionStore::new();
        let session = store.begin(code.expose_secret()).unwrap();
        let pending = store.checkout(session.session_id).unwrap();
        assert_eq!(store.pending_count(), 0);
        assert_eq!(pending.setup_invitation(), code.expose_secret());
        assert!(!format!("{pending:?}").contains(code.expose_secret()));
        assert!(store.restore(session.session_id, pending).unwrap());
        assert_eq!(store.pending_count(), 1);
        assert!(store.cancel(session.session_id).unwrap());
    }
}
