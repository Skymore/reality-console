use crate::{
    bootstrap_and_install_user_service, inspect_setup_code, BootstrapRequest,
    BootstrapServiceOutcome, EnrollmentState, NodeSetupPreview, UserServiceInstallRequest,
};
use anyhow::{bail, Context as _, Result};
use serde::Serialize;
use std::collections::BTreeMap;
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
}
