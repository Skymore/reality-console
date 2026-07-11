use assert_cmd::Command;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, verify_enrollment_proof,
    EnrollmentInvitation,
};
use control_protocol::id::{
    ControllerInstanceId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, Timestamp,
};
use control_protocol::node::{
    CreateNodeInvitationResponse, EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode,
    NodeCapability, NodeCredential, PairingPurpose,
};
use control_protocol::secret::Secret;
use ed25519_dalek::{Signer as _, SigningKey};
use node_host::{bootstrap, join, status, BootstrapRequest, EnrollmentState};
use predicates::prelude::*;
use rand_core::{OsRng, RngCore as _};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const INVITATION_SECRET: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

#[cfg(unix)]
struct FakeXray {
    _directory: tempfile::TempDir,
    path: PathBuf,
    digest: String,
}

#[cfg(unix)]
impl FakeXray {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray");
        let script = b"#!/bin/sh\nif [ \"$#\" -eq 1 ] && [ \"$1\" = \"version\" ]; then printf 'Xray 25.7.1\\n'; exit 0; fi\nexit 64\n";
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _directory: directory,
            path,
            digest: format!("{:x}", Sha256::digest(script)),
        }
    }
}

#[derive(Clone, Copy)]
enum ResponseMode {
    Valid,
    InvalidProof,
    FingerprintMismatch,
    RetryOnce,
}

#[derive(Clone)]
struct MockState {
    invitation: CreateNodeInvitationResponse,
    signing_key: Arc<SigningKey>,
    network_id: NetworkId,
    node_id: NodeId,
    controller_instance_id: ControllerInstanceId,
    credential_key_id: NodeKeyId,
    credential_expires_at: Timestamp,
    mode: ResponseMode,
    request_count: Arc<AtomicUsize>,
}

struct MockController {
    invitation: CreateNodeInvitationResponse,
    request_count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl MockController {
    async fn start(mode: ResponseMode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let signing_key = Arc::new(random_signing_key());
        let pinned_key = if matches!(mode, ResponseMode::FingerprintMismatch) {
            random_signing_key()
        } else {
            SigningKey::from_bytes(&signing_key.to_bytes())
        };
        let invitation = CreateNodeInvitationResponse {
            invitation_id: NodeInvitationId::new(),
            purpose: PairingPurpose::NodeEnrollment,
            expires_at: Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::hours(1)),
            invitation_secret: Secret::new(INVITATION_SECRET.to_string()),
            controller_origin: origin,
            controller_fingerprint: fingerprint(&pinned_key),
        };
        let request_count = Arc::new(AtomicUsize::new(0));
        let state = MockState {
            invitation: invitation.clone(),
            signing_key,
            network_id: NetworkId::new(),
            node_id: NodeId::new(),
            controller_instance_id: ControllerInstanceId::new(),
            credential_key_id: NodeKeyId::new(),
            credential_expires_at: Timestamp::from_datetime(
                OffsetDateTime::now_utc() + Duration::days(30),
            ),
            mode,
            request_count: Arc::clone(&request_count),
        };
        let router = Router::new()
            .route("/v1/nodes/enroll", post(enroll))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve mock controller");
        });
        Self {
            invitation,
            request_count,
            task,
        }
    }

    fn write_invitation(&self, path: &std::path::Path) {
        fs::write(path, serde_json::to_vec(&self.invitation).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

impl Drop for MockController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn enroll(
    State(state): State<MockState>,
    Json(request): Json<EnrollNodeRequest>,
) -> Response {
    let attempt = state.request_count.fetch_add(1, Ordering::SeqCst);
    if matches!(state.mode, ResponseMode::RetryOnce) && attempt == 0 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if request.invitation_secret != state.invitation.invitation_secret {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut expected_capabilities = vec![NodeCapability::Xray, NodeCapability::DirectTcp];
    if request.provider_consent.router_mapping_accepted {
        expected_capabilities.extend([
            NodeCapability::Pcp,
            NodeCapability::NatPmp,
            NodeCapability::Upnp,
        ]);
    }
    if request.capabilities != expected_capabilities {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let invitation = EnrollmentInvitation {
        invitation_id: state.invitation.invitation_id,
        purpose: state.invitation.purpose,
        expires_at: state.invitation.expires_at,
        controller_origin: &state.invitation.controller_origin,
        controller_fingerprint: &state.invitation.controller_fingerprint,
    };
    let request_transcript = enrollment_request_transcript(&invitation, &request).unwrap();
    if verify_enrollment_proof(&request, &request_transcript).is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let public_key = public_key(&state.signing_key);
    let mut response = EnrollNodeResponse {
        network_id: state.network_id,
        node_id: state.node_id,
        controller_instance_id: state.controller_instance_id,
        credential: NodeCredential {
            key_id: state.credential_key_id,
            mode: NodeAuthenticationMode::SignedRequest,
            expires_at: state.credential_expires_at,
            client_certificate_pem: None,
        },
        desired_state_signing_public_key: public_key,
        controller_nonce: Nonce::from_str(&URL_SAFE_NO_PAD.encode([23_u8; 32])).unwrap(),
        proof: zero_signature(),
    };
    let transcript = enrollment_response_transcript(&request_transcript, &response).unwrap();
    response.proof = if matches!(state.mode, ResponseMode::InvalidProof) {
        zero_signature()
    } else {
        Ed25519Signature::from_str(
            &URL_SAFE_NO_PAD.encode(state.signing_key.sign(&transcript).to_bytes()),
        )
        .unwrap()
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn happy_path_persists_verified_metadata_without_secrets() {
    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    let joined = join(&data_dir, &invitation_file, "Friend's Mac", true, true)
        .await
        .unwrap();
    assert_eq!(joined.enrollment_state, EnrollmentState::Enrolled);
    assert!(joined.node_id.is_some());
    assert!(joined.credential_expires_at.is_some());

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let registration_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM enrollment_registration", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(registration_count, 1);
    drop(connection);

    let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
    assert!(!contains_bytes(&database, INVITATION_SECRET.as_bytes()));
    let output = Command::cargo_bin("node-host")
        .unwrap()
        .args(["status", "--data-dir"])
        .arg(&data_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("enrollment: enrolled"))
        .get_output()
        .stdout
        .clone();
    assert!(!contains_bytes(&output, INVITATION_SECRET.as_bytes()));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_bootstrap_verifies_runtime_then_enrolls_in_one_call() {
    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let fake = FakeXray::new();
    let invitation_json = serde_json::to_vec(&controller.invitation).unwrap();
    let request = BootstrapRequest::from_invitation_json(
        &invitation_json,
        "Friend Mac",
        fake.path.clone(),
        fake.digest.clone(),
        true,
        true,
        true,
    )
    .unwrap();

    let joined = bootstrap(&data_dir, request).await.unwrap();

    assert_eq!(joined.enrollment_state, EnrollmentState::Enrolled);
    assert!(joined.xray_configured);
    assert!(joined.router_mapping.enabled);
    assert_eq!(
        joined.router_mapping.state,
        node_host::RouterMappingState::Waiting
    );
    assert_eq!(
        joined.xray_binary_path.as_deref(),
        Some(fake.path.as_path())
    );
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 1);
    assert!(!temp.path().join("invitation.json").exists());
    let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
    assert!(!contains_bytes(&database, INVITATION_SECRET.as_bytes()));
}

#[cfg(unix)]
#[tokio::test]
async fn bootstrap_rejects_a_bad_runtime_before_consuming_the_invitation() {
    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let fake = FakeXray::new();
    let invitation_json = serde_json::to_vec(&controller.invitation).unwrap();
    let request = BootstrapRequest::from_invitation_json(
        &invitation_json,
        "Friend Mac",
        fake.path,
        "00".repeat(32),
        true,
        true,
        false,
    )
    .unwrap();

    let error = bootstrap(&data_dir, request).await.unwrap_err();

    assert!(error.to_string().contains("bundled Xray runtime"));
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 0);
    let current = status(&data_dir).unwrap();
    assert_eq!(current.enrollment_state, EnrollmentState::NotEnrolled);
    assert!(!current.xray_configured);
    assert!(!data_dir.join("reality.x25519.seed").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn bootstrap_requires_consent_before_creating_local_state() {
    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let fake = FakeXray::new();
    let invitation_json = serde_json::to_vec(&controller.invitation).unwrap();
    let request = BootstrapRequest::from_invitation_json(
        &invitation_json,
        "Friend Mac",
        fake.path,
        fake.digest,
        true,
        false,
        false,
    )
    .unwrap();

    let error = bootstrap(&data_dir, request).await.unwrap_err();

    assert!(error.to_string().contains("explicit provider consent"));
    assert!(!data_dir.exists());
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retrying_bootstrap_reuses_local_identity_and_verified_runtime() {
    let controller = MockController::start(ResponseMode::RetryOnce).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let fake = FakeXray::new();
    let invitation_json = serde_json::to_vec(&controller.invitation).unwrap();

    let first_request = BootstrapRequest::from_invitation_json(
        &invitation_json,
        "Friend Mac",
        fake.path.clone(),
        fake.digest.clone(),
        true,
        true,
        true,
    )
    .unwrap();
    bootstrap(&data_dir, first_request).await.unwrap_err();
    let before = status(&data_dir).unwrap();
    assert_eq!(before.enrollment_state, EnrollmentState::NotEnrolled);
    assert!(before.xray_configured);

    let retry_request = BootstrapRequest::from_invitation_json(
        &invitation_json,
        "Friend Mac",
        fake.path,
        fake.digest,
        true,
        true,
        true,
    )
    .unwrap();
    let joined = bootstrap(&data_dir, retry_request).await.unwrap();

    assert_eq!(joined.identity_public_key, before.identity_public_key);
    assert_eq!(joined.encryption_public_key, before.encryption_public_key);
    assert_eq!(joined.reality_public_key, before.reality_public_key);
    assert_eq!(joined.enrollment_state, EnrollmentState::Enrolled);
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn invalid_controller_proof_is_rejected_without_registration() {
    let controller = MockController::start(ResponseMode::InvalidProof).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    let error = join(&data_dir, &invitation_file, "Friend Mac", true, true)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("proof is invalid"));
    assert!(!error.to_string().contains(INVITATION_SECRET));
    assert_not_enrolled(&data_dir);
}

#[tokio::test]
async fn controller_key_fingerprint_must_match_invitation() {
    let controller = MockController::start(ResponseMode::FingerprintMismatch).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    let error = join(&data_dir, &invitation_file, "Friend Mac", true, true)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("fingerprint"));
    assert!(!error.to_string().contains(INVITATION_SECRET));
    assert_not_enrolled(&data_dir);
}

#[tokio::test]
async fn repeated_join_recovers_with_the_same_local_identity() {
    let controller = MockController::start(ResponseMode::RetryOnce).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    join(&data_dir, &invitation_file, "Friend Mac", true, true)
        .await
        .unwrap_err();
    let before = status(&data_dir).unwrap();
    assert_eq!(before.enrollment_state, EnrollmentState::NotEnrolled);
    let joined = join(&data_dir, &invitation_file, "Friend Mac", true, true)
        .await
        .unwrap();
    assert_eq!(joined.identity_public_key, before.identity_public_key);
    assert_eq!(joined.encryption_public_key, before.encryption_public_key);
    assert_eq!(joined.enrollment_state, EnrollmentState::Enrolled);
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn both_consent_flags_are_required_before_initialization() {
    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    let error = join(&data_dir, &invitation_file, "Friend Mac", true, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("--accept-exit-ip"));
    assert!(!data_dir.exists());
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn invitation_file_must_be_owner_only_and_not_a_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let controller = MockController::start(ResponseMode::Valid).await;
    let temp = tempfile::tempdir().unwrap();
    let invitation_file = temp.path().join("invitation.json");
    let data_dir = temp.path().join("state");
    controller.write_invitation(&invitation_file);

    fs::set_permissions(&invitation_file, fs::Permissions::from_mode(0o644)).unwrap();
    let insecure = join(&data_dir, &invitation_file, "Friend Mac", true, true)
        .await
        .unwrap_err();
    assert!(insecure.to_string().contains("group or other users"));

    fs::set_permissions(&invitation_file, fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.path().join("invitation-link.json");
    symlink(&invitation_file, &link).unwrap();
    let linked = join(&data_dir, &link, "Friend Mac", true, true)
        .await
        .unwrap_err();
    assert!(linked.to_string().contains("non-symlink"));
    assert_eq!(controller.request_count.load(Ordering::SeqCst), 0);
}

fn assert_not_enrolled(data_dir: &std::path::Path) {
    let current = status(data_dir).unwrap();
    assert_eq!(current.enrollment_state, EnrollmentState::NotEnrolled);
    assert!(current.node_id.is_none());
    assert!(current.credential_expires_at.is_none());
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM enrollment_registration", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

fn fingerprint(key: &SigningKey) -> Sha256Digest {
    let digest = Sha256::digest(key.verifying_key().to_bytes());
    Sha256Digest::from_str(&format!("sha256:{digest:x}")).unwrap()
}

fn random_signing_key() -> SigningKey {
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn public_key(key: &SigningKey) -> Ed25519PublicKey {
    Ed25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())).unwrap()
}

fn zero_signature() -> Ed25519Signature {
    Ed25519Signature::from_str(&URL_SAFE_NO_PAD.encode([0_u8; 64])).unwrap()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
