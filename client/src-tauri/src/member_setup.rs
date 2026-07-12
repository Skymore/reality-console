//! Secret-minimizing member setup ingestion for the desktop backend.

use crate::control_api::validate_origin;
use crate::error::ClientError;
use control_protocol::account::{decode_member_setup_code, MEMBER_SETUP_CODE_PREFIX};
use control_protocol::crypto::Ed25519PublicKey;
use control_protocol::id::{
    ControllerInstanceId, DeviceActivationId, NetworkId, Timestamp, UserId,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_SETUP_LINK_LENGTH: usize = 8_192;
const MAX_PENDING_SETUP_SESSIONS: usize = 8;

/// Secret-free setup information returned to the renderer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSetupPreview {
    /// Controller-selected member label.
    pub display_name: String,
    /// Canonical pinned Control origin.
    pub controller_origin: String,
    /// Hard one-time activation deadline.
    pub expires_at: Timestamp,
}

/// Random renderer handle plus the only setup fields safe to preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberSetupSession {
    /// Random process-local handle, never a Control credential.
    pub session_id: Uuid,
    /// Secret-free confirmation details.
    pub preview: MemberSetupPreview,
}

/// Backend-only decoded setup values.
pub(crate) struct MemberSetupMaterial {
    pub(crate) controller_origin: Url,
    pub(crate) network_id: NetworkId,
    pub(crate) user_id: UserId,
    pub(crate) activation_id: DeviceActivationId,
    pub(crate) activation_secret: Zeroizing<String>,
    pub(crate) expires_at: Timestamp,
    pub(crate) controller_instance_id: ControllerInstanceId,
    pub(crate) controller_signing_key: Ed25519PublicKey,
}

impl std::fmt::Debug for MemberSetupMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemberSetupMaterial")
            .field("controller_origin", &self.controller_origin)
            .field("network_id", &"[redacted]")
            .field("user_id", &"[redacted]")
            .field("activation_id", &"[redacted]")
            .field("activation_secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("controller_instance_id", &"[redacted]")
            .field("controller_signing_key", &"[redacted]")
            .finish()
    }
}

struct PendingSetup {
    material: MemberSetupMaterial,
    preview: MemberSetupPreview,
}

pub(crate) struct CheckedOutSetup(PendingSetup);

impl CheckedOutSetup {
    pub(crate) fn expires_at(&self) -> Timestamp {
        self.0.preview.expires_at
    }

    pub(crate) fn material(&self) -> &MemberSetupMaterial {
        &self.0.material
    }
}

/// Process-local owner of pending member activation bearer material.
pub struct SetupSessionStore {
    sessions: Mutex<BTreeMap<Uuid, PendingSetup>>,
}

impl Default for SetupSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupSessionStore {
    /// Creates an empty bounded setup store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
        }
    }

    /// Parses one setup code/link and retains all sensitive values in this process only.
    pub fn begin(&self, input: &str) -> Result<MemberSetupSession, ClientError> {
        self.begin_at(input, OffsetDateTime::now_utc())
    }

    fn begin_at(
        &self,
        input: &str,
        now: OffsetDateTime,
    ) -> Result<MemberSetupSession, ClientError> {
        let (material, preview) = decode_setup_input(input)?;
        if preview.expires_at.as_datetime() <= now {
            return Err(setup_error("member_setup_expired"));
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| setup_error("member_setup_store_unavailable"))?;
        sessions.retain(|_, pending| pending.preview.expires_at.as_datetime() > now);
        if sessions.len() >= MAX_PENDING_SETUP_SESSIONS {
            return Err(setup_error("member_setup_store_full"));
        }
        let session_id = Uuid::new_v4();
        sessions.insert(
            session_id,
            PendingSetup {
                material,
                preview: preview.clone(),
            },
        );
        Ok(MemberSetupSession {
            session_id,
            preview,
        })
    }

    /// Cancels a pending setup and immediately drops its zeroizing bearer.
    pub fn cancel(&self, session_id: Uuid) -> Result<bool, ClientError> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| setup_error("member_setup_store_unavailable"))?
            .remove(&session_id)
            .is_some())
    }

    pub(crate) fn checkout(&self, session_id: Uuid) -> Result<CheckedOutSetup, ClientError> {
        self.sessions
            .lock()
            .map_err(|_| setup_error("member_setup_store_unavailable"))?
            .remove(&session_id)
            .map(CheckedOutSetup)
            .ok_or_else(|| setup_error("member_setup_session_missing"))
    }

    pub(crate) fn restore(
        &self,
        session_id: Uuid,
        checked_out: CheckedOutSetup,
    ) -> Result<(), ClientError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| setup_error("member_setup_store_unavailable"))?;
        if sessions.contains_key(&session_id) {
            return Err(setup_error("member_setup_session_conflict"));
        }
        sessions.insert(session_id, checked_out.0);
        Ok(())
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

fn decode_setup_input(
    input: &str,
) -> Result<(MemberSetupMaterial, MemberSetupPreview), ClientError> {
    let input = input.trim();
    if input.starts_with(MEMBER_SETUP_CODE_PREFIX) {
        return decode_setup_code(input, None);
    }
    if input.len() > MAX_SETUP_LINK_LENGTH {
        return Err(setup_error("member_setup_input_too_large"));
    }
    let link = Url::parse(input).map_err(|_| setup_error("member_setup_link_invalid"))?;
    let mut link_origin = link.clone();
    link_origin.set_path("/");
    link_origin.set_query(None);
    link_origin.set_fragment(None);
    validate_origin(&link_origin).map_err(|_| setup_error("member_setup_origin_invalid"))?;
    if link.path() != "/join/connect"
        || link.query().is_some()
        || !link.username().is_empty()
        || link.password().is_some()
    {
        return Err(setup_error("member_setup_link_invalid"));
    }
    let code = link
        .fragment()
        .ok_or_else(|| setup_error("member_setup_fragment_missing"))?;
    decode_setup_code(code, Some(&link_origin))
}

fn decode_setup_code(
    code: &str,
    expected_origin: Option<&Url>,
) -> Result<(MemberSetupMaterial, MemberSetupPreview), ClientError> {
    let activation =
        decode_member_setup_code(code).map_err(|_| setup_error("member_setup_code_invalid"))?;
    let controller_origin = Url::parse(&activation.controller_origin)
        .map_err(|_| setup_error("member_setup_origin_invalid"))?;
    validate_origin(&controller_origin).map_err(|_| setup_error("member_setup_origin_invalid"))?;
    if expected_origin.is_some_and(|origin| origin.origin() != controller_origin.origin()) {
        return Err(setup_error("member_setup_origin_mismatch"));
    }
    let canonical_origin = controller_origin.origin().ascii_serialization();
    let preview = MemberSetupPreview {
        display_name: activation.display_name,
        controller_origin: canonical_origin,
        expires_at: activation.expires_at,
    };
    Ok((
        MemberSetupMaterial {
            controller_origin,
            network_id: activation.network_id,
            user_id: activation.user_id,
            activation_id: activation.activation_id,
            activation_secret: Zeroizing::new(activation.activation_secret.into_inner()),
            expires_at: activation.expires_at,
            controller_instance_id: activation.controller_instance_id,
            controller_signing_key: activation.bundle_signing_public_key,
        },
        preview,
    ))
}

fn setup_error(code: &str) -> ClientError {
    ClientError::internal(code, "The member setup operation failed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use control_protocol::account::{encode_member_setup_code, MemberSetupActivation};
    use control_protocol::secret::Secret;
    use time::Duration;

    struct Fixture {
        code: String,
        network_id: NetworkId,
        user_id: UserId,
        activation_id: DeviceActivationId,
        controller_instance_id: ControllerInstanceId,
        public_key: String,
        secret: String,
        expires_at: Timestamp,
    }

    impl Fixture {
        fn new(origin: &str, expires_at: OffsetDateTime) -> Self {
            let network_id = NetworkId::new();
            let user_id = UserId::new();
            let activation_id = DeviceActivationId::new();
            let controller_instance_id = ControllerInstanceId::new();
            let public_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
            let secret = format!(
                "rcd1.{activation_id}.{}",
                URL_SAFE_NO_PAD.encode([9_u8; 32])
            );
            let expires_at = Timestamp::from_datetime(expires_at);
            let activation = MemberSetupActivation {
                display_name: "Friend account".to_string(),
                network_id,
                user_id,
                activation_id,
                expires_at,
                activation_secret: Secret::new(secret.clone()),
                controller_origin: origin.trim_end_matches('/').to_string(),
                controller_instance_id,
                bundle_signing_public_key: public_key.parse().unwrap(),
            };
            Self {
                code: encode_member_setup_code(&activation).unwrap().into_inner(),
                network_id,
                user_id,
                activation_id,
                controller_instance_id,
                public_key,
                secret,
                expires_at,
            }
        }
    }

    #[test]
    fn renderer_preview_serialization_contains_no_ids_secret_or_public_key() {
        let now = OffsetDateTime::now_utc();
        let fixture = Fixture::new("https://control.example/", now + Duration::minutes(5));
        let store = SetupSessionStore::new();
        let session = store.begin_at(&fixture.code, now).unwrap();

        let serialized = serde_json::to_string(&session).unwrap();
        for forbidden in [
            fixture.network_id.to_string(),
            fixture.user_id.to_string(),
            fixture.activation_id.to_string(),
            fixture.controller_instance_id.to_string(),
            fixture.public_key,
            fixture.secret,
        ] {
            assert!(!serialized.contains(&forbidden));
        }
        assert_eq!(session.preview.display_name, "Friend account");
        assert_eq!(session.preview.controller_origin, "https://control.example");
        assert_eq!(session.preview.expires_at, fixture.expires_at);
    }

    #[test]
    fn strict_fragment_link_requires_exact_payload_origin() {
        let now = OffsetDateTime::now_utc();
        let fixture = Fixture::new("https://control.example/", now + Duration::minutes(5));
        let store = SetupSessionStore::new();
        let valid = format!("https://control.example/join/connect#{}", fixture.code);
        assert!(store.begin_at(&valid, now).is_ok());

        let mismatch = format!("https://other.example/join/connect#{}", fixture.code);
        assert_eq!(
            store.begin_at(&mismatch, now).unwrap_err().code,
            "member_setup_origin_mismatch"
        );
        for invalid in [
            format!("http://control.example/join/connect#{}", fixture.code),
            format!("https://control.example/join/connect?x=1#{}", fixture.code),
            format!("https://control.example/join/node#{}", fixture.code),
        ] {
            assert!(store.begin_at(&invalid, now).is_err());
        }
    }

    #[test]
    fn loopback_http_is_allowed_but_only_for_the_same_origin() {
        let now = OffsetDateTime::now_utc();
        let fixture = Fixture::new("http://127.0.0.1:8787/", now + Duration::minutes(5));
        let link = format!("http://127.0.0.1:8787/join/connect#{}", fixture.code);
        assert!(SetupSessionStore::new().begin_at(&link, now).is_ok());
    }

    #[test]
    fn expired_setup_is_rejected_and_pruned() {
        let now = OffsetDateTime::now_utc();
        let expired = Fixture::new("https://control.example/", now - Duration::seconds(1));
        assert_eq!(
            SetupSessionStore::new()
                .begin_at(&expired.code, now)
                .unwrap_err()
                .code,
            "member_setup_expired"
        );
    }

    #[test]
    fn exact_retry_restores_the_same_checked_out_bearer_and_cancel_cleans_it() {
        let now = OffsetDateTime::now_utc();
        let fixture = Fixture::new("https://control.example/", now + Duration::minutes(5));
        let store = SetupSessionStore::new();
        let session = store.begin_at(&fixture.code, now).unwrap();
        let first = store.checkout(session.session_id).unwrap();
        assert_eq!(first.0.material.activation_secret.as_str(), fixture.secret);
        store.restore(session.session_id, first).unwrap();

        let retry = store.checkout(session.session_id).unwrap();
        assert_eq!(retry.0.material.activation_secret.as_str(), fixture.secret);
        store.restore(session.session_id, retry).unwrap();
        assert!(store.cancel(session.session_id).unwrap());
        assert_eq!(store.pending_count(), 0);
    }
}
