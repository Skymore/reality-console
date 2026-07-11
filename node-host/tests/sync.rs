use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{ed25519_signing_key_id, Ed25519PublicKey, Ed25519Signature};
use control_protocol::desired::desired_state_transcript;
use control_protocol::error::ErrorCode;
use control_protocol::id::{
    ControllerInstanceId, CredentialId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, RequestId,
    Revision, SequenceNumber, SigningKeyId, Timestamp, UserId,
};
use control_protocol::node::{
    DesiredStateDocument, DesiredUser, DesiredXrayState, EndpointReadiness, NodeEndpointStatus,
    NodeHeartbeat, NodeHeartbeatStatus, NodeLifecycleState, NodeRuntimeState, RevisionResult,
    RevisionResultState, SignedDesiredState, SignedNodeHeartbeatStatus,
};
use control_protocol::node_status::node_heartbeat_status_transcript;
use control_protocol::request_auth::{
    verify_node_request_signature, NodeRequestAuthHeaders, NodeRequestSigningInput,
};
use control_protocol::secret::Secret;
use ed25519_dalek::{Signer as _, SigningKey};
#[cfg(unix)]
use node_host::configure_xray;
#[cfg(target_os = "macos")]
use node_host::query_local_service_status;
use node_host::{initialize, run_until, status, sync_once, EnrollmentState, SyncLoopOptions};
use rusqlite::{params, Connection};
use serde_json::json;
#[cfg(unix)]
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use std::fmt::Write as _;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};

const SECRET_RESPONSE_TEXT: &str = "controller-private-debug-secret";
#[cfg(unix)]
const SECRET_XRAY_OUTPUT: &str = "xray-private-config-debug-secret";

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum FakeConfigMode {
    Valid,
    Reject,
}

#[cfg(unix)]
struct FakeXray {
    _directory: tempfile::TempDir,
    path: PathBuf,
    digest: String,
    script: Vec<u8>,
}

#[cfg(unix)]
impl FakeXray {
    fn new(mode: FakeConfigMode) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray");
        let config_exit = match mode {
            FakeConfigMode::Valid => 0,
            FakeConfigMode::Reject => 42,
        };
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$#\" -eq 1 ] && [ \"$1\" = \"version\" ]; then\n\
               printf 'Xray 25.7.1\\n'\n\
               exit 0\n\
             fi\n\
             if [ \"$#\" -eq 4 ] && [ \"$1\" = \"run\" ] && [ \"$2\" = \"-test\" ] && [ \"$3\" = \"-config\" ] && [ -r \"$4\" ]; then\n\
               printf '{SECRET_XRAY_OUTPUT}\\n' >&2\n\
               exit {config_exit}\n\
             fi\n\
             exit 64\n"
        )
        .into_bytes();
        write_executable(&path, &script);
        Self {
            _directory: directory,
            path,
            digest: sha256_hex(&script),
            script,
        }
    }

    fn tamper(&self) {
        let mut tampered = self.script.clone();
        tampered.extend_from_slice(b"# modified after pinning\n");
        write_executable(&self.path, &tampered);
    }

    fn restore(&self) {
        write_executable(&self.path, &self.script);
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

#[derive(Debug, Clone, Copy)]
enum ResponseMode {
    NoDesiredState,
    RejectHeartbeat,
    UnverifiedDesiredState,
    VerifiedDesiredState,
}

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
struct MockState {
    mode: ResponseMode,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    desired: Arc<Mutex<Option<SignedDesiredState>>>,
    heartbeat_status: Arc<Mutex<Option<SignedNodeHeartbeatStatus>>>,
    reject_revision_results: Arc<AtomicBool>,
}

struct MockController {
    origin: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    desired: Arc<Mutex<Option<SignedDesiredState>>>,
    heartbeat_status: Arc<Mutex<Option<SignedNodeHeartbeatStatus>>>,
    reject_revision_results: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl MockController {
    async fn start(mode: ResponseMode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock controller");
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let desired = Arc::new(Mutex::new(None));
        let heartbeat_status = Arc::new(Mutex::new(None));
        let reject_revision_results = Arc::new(AtomicBool::new(false));
        let state = MockState {
            mode,
            requests: Arc::clone(&requests),
            desired: Arc::clone(&desired),
            heartbeat_status: Arc::clone(&heartbeat_status),
            reject_revision_results: Arc::clone(&reject_revision_results),
        };
        let router = Router::new()
            .route("/v1/nodes/{node_id}/heartbeat", post(capture))
            .route("/v1/nodes/{node_id}/desired", get(capture))
            .route(
                "/v1/nodes/{node_id}/revisions/{revision}/result",
                put(capture),
            )
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve mock controller");
        });
        Self {
            origin,
            requests,
            desired,
            heartbeat_status,
            reject_revision_results,
            task,
        }
    }

    fn captured(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn clear_captured(&self) {
        self.requests.lock().unwrap().clear();
    }

    fn set_desired(&self, desired: SignedDesiredState) {
        *self.desired.lock().unwrap() = Some(desired);
    }

    fn set_heartbeat_status(&self, status: SignedNodeHeartbeatStatus) {
        *self.heartbeat_status.lock().unwrap() = Some(status);
    }

    fn clear_heartbeat_status(&self) {
        *self.heartbeat_status.lock().unwrap() = None;
    }

    fn reject_revision_results(&self, reject: bool) {
        self.reject_revision_results.store(reject, Ordering::SeqCst);
    }
}

impl Drop for MockController {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn capture(
    State(state): State<MockState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path_and_query = uri
        .path_and_query()
        .expect("request target")
        .as_str()
        .to_string();
    state.requests.lock().unwrap().push(CapturedRequest {
        method,
        path_and_query: path_and_query.clone(),
        headers,
        body: body.to_vec(),
    });

    if path_and_query.ends_with("/heartbeat") {
        if matches!(state.mode, ResponseMode::RejectHeartbeat) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({
                    "error": {
                        "code": "authentication_failed",
                        "message": SECRET_RESPONSE_TEXT,
                        "requestId": RequestId::new(),
                        "retryable": false,
                        "details": {"private": SECRET_RESPONSE_TEXT}
                    }
                })),
            )
                .into_response();
        }
        return state.heartbeat_status.lock().unwrap().clone().map_or_else(
            || StatusCode::NO_CONTENT.into_response(),
            |status| (StatusCode::OK, axum::Json(status)).into_response(),
        );
    }

    if path_and_query.ends_with("/result") {
        if state.reject_revision_results.load(Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(json!({
                    "error": {
                        "code": "service_unavailable",
                        "message": SECRET_RESPONSE_TEXT,
                        "requestId": RequestId::new(),
                        "retryable": true,
                        "details": {"private": SECRET_RESPONSE_TEXT}
                    }
                })),
            )
                .into_response();
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    match state.mode {
        ResponseMode::UnverifiedDesiredState => (
            StatusCode::OK,
            axum::Json(json!({"unverified": SECRET_RESPONSE_TEXT})),
        )
            .into_response(),
        ResponseMode::VerifiedDesiredState => {
            let desired = state
                .desired
                .lock()
                .unwrap()
                .clone()
                .expect("verified desired response");
            let after_revision = path_and_query
                .split("afterRevision=")
                .nth(1)
                .and_then(|value| value.parse::<i64>().ok())
                .expect("desired revision query");
            if after_revision >= desired.document.revision.get() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (StatusCode::OK, axum::Json(desired)).into_response()
            }
        }
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

#[derive(Debug, Clone, Copy)]
struct Registration {
    network: NetworkId,
    node: NodeId,
    key: NodeKeyId,
    controller_instance: ControllerInstanceId,
}

fn install_registration(data_dir: &std::path::Path, origin: &str) -> Registration {
    let initialized = initialize(data_dir, origin).expect("initialize node host");
    let registration = Registration {
        network: NetworkId::new(),
        node: NodeId::new(),
        key: NodeKeyId::new(),
        controller_instance: ControllerInstanceId::new(),
    };
    let expires_at = Timestamp::from_datetime(OffsetDateTime::now_utc() + Duration::days(30));
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO enrollment_registration(
                singleton, invitation_id, network_id, node_id, controller_instance_id,
                controller_fingerprint, controller_signing_public_key, credential_key_id,
                credential_mode, credential_expires_at, enrolled_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'signedRequest', ?8, ?9)",
            params![
                NodeInvitationId::new().to_string(),
                registration.network.to_string(),
                registration.node.to_string(),
                registration.controller_instance.to_string(),
                format!("sha256:{}", "0".repeat(64)),
                initialized.identity_public_key.as_str(),
                registration.key.to_string(),
                expires_at.to_string(),
                OffsetDateTime::now_utc().unix_timestamp(),
            ],
        )
        .unwrap();
    registration
}

fn signed_desired(
    data_dir: &std::path::Path,
    registration: Registration,
    revision: i64,
) -> SignedDesiredState {
    signed_desired_for_schema(
        data_dir,
        registration,
        revision,
        control_protocol::version::DESIRED_STATE_SCHEMA_VERSION,
    )
}

fn signed_desired_for_schema(
    data_dir: &std::path::Path,
    registration: Registration,
    revision: i64,
    schema_version: u16,
) -> SignedDesiredState {
    let signing_seed: [u8; 32] = fs::read(data_dir.join("identity.ed25519.seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signing_public_key: Ed25519PublicKey = URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().to_bytes())
        .parse()
        .unwrap();
    let (listen_port, public_port) = match schema_version {
        1 => (443, None),
        2 => (10_443, Some(443)),
        _ => panic!("unsupported test desired-state schema"),
    };
    let document = DesiredStateDocument {
        schema_version,
        network_id: registration.network,
        node_id: registration.node,
        revision: Revision::new(revision).unwrap(),
        created_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
        min_agent_version: "0.1.0".to_string(),
        users: vec![DesiredUser {
            user_id: UserId::new(),
            credential_id: CredentialId::new(),
            vless_uuid: Secret::new("2f55c837-7be6-4752-b58a-a7f51401bd89".to_string()),
            enabled: true,
        }],
        xray: DesiredXrayState {
            listen_port,
            public_port,
            server_names: vec!["www.microsoft.com".to_string()],
            target: "www.microsoft.com:443".to_string(),
        },
        signing_key_id: ed25519_signing_key_id(&signing_public_key).unwrap(),
        controller_instance_id: registration.controller_instance,
    };
    let signature: Ed25519Signature = URL_SAFE_NO_PAD
        .encode(
            signing_key
                .sign(&desired_state_transcript(&document).unwrap())
                .to_bytes(),
        )
        .parse()
        .unwrap();
    SignedDesiredState {
        document,
        signature,
    }
}

fn signed_controller_status(
    data_dir: &std::path::Path,
    registration: Registration,
    heartbeat_generation: i64,
) -> SignedNodeHeartbeatStatus {
    let signing_seed: [u8; 32] = fs::read(data_dir.join("identity.ed25519.seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let signing_public_key: Ed25519PublicKey = URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().to_bytes())
        .parse()
        .unwrap();
    let observed_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let document = NodeHeartbeatStatus {
        schema_version: 1,
        node_id: registration.node,
        heartbeat_generation: SequenceNumber::new(heartbeat_generation).unwrap(),
        observed_at,
        lifecycle: NodeLifecycleState::Active,
        endpoints: vec![NodeEndpointStatus {
            endpoint_id: control_protocol::id::EndpointId::new(),
            readiness: EndpointReadiness::TcpReachable,
            last_checked_at: Some(observed_at),
            error_code: None,
        }],
        signing_key_id: ed25519_signing_key_id(&signing_public_key).unwrap(),
        controller_instance_id: registration.controller_instance,
    };
    let signature: Ed25519Signature = URL_SAFE_NO_PAD
        .encode(
            signing_key
                .sign(&node_heartbeat_status_transcript(&document).unwrap())
                .to_bytes(),
        )
        .parse()
        .unwrap();
    SignedNodeHeartbeatStatus {
        document,
        signature,
    }
}

fn resign_controller_status(data_dir: &std::path::Path, status: &mut SignedNodeHeartbeatStatus) {
    let signing_seed: [u8; 32] = fs::read(data_dir.join("identity.ed25519.seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    status.signature = URL_SAFE_NO_PAD
        .encode(
            signing_key
                .sign(&node_heartbeat_status_transcript(&status.document).unwrap())
                .to_bytes(),
        )
        .parse()
        .unwrap();
}

async fn assert_rejected_controller_status<F>(mutate: F, resign: bool, expected_error: &str)
where
    F: FnOnce(&mut SignedNodeHeartbeatStatus),
{
    let controller = MockController::start(ResponseMode::NoDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let mut response = signed_controller_status(&data_dir, registration, 1);
    mutate(&mut response);
    if resign {
        resign_controller_status(&data_dir, &mut response);
    }
    controller.set_heartbeat_status(response);

    let error = sync_once(&data_dir).await.unwrap_err();
    assert!(format!("{error:#}").contains(expected_error));
    let current = status(&data_dir).unwrap();
    assert!(current.last_heartbeat_at.is_none());
    assert!(current.controller_status.is_none());
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let persisted: i64 = connection
        .query_row("SELECT COUNT(*) FROM controller_status_state", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(persisted, 0);
}

#[tokio::test]
async fn sync_signs_exact_requests_with_unique_nonces_and_persists_success() {
    let controller = MockController::start(ResponseMode::NoDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let public_key = status(&data_dir).unwrap().identity_public_key;

    let synced = sync_once(&data_dir).await.unwrap();
    assert_eq!(synced.enrollment_state, EnrollmentState::Enrolled);
    assert!(synced.last_heartbeat_at.is_some());
    assert!(synced.last_sync_at.is_some());
    assert!(synced.controller_status.is_none());
    assert_eq!(synced.desired_revision_cursor, 0);
    assert_eq!(synced.schema_version, 11);

    let captured = controller.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].method, Method::POST);
    assert_eq!(
        captured[0].path_and_query,
        format!("/v1/nodes/{}/heartbeat", registration.node)
    );
    let heartbeat: NodeHeartbeat = serde_json::from_slice(&captured[0].body).unwrap();
    assert_eq!(heartbeat.heartbeat_generation.get(), 1);
    assert_eq!(heartbeat.state, NodeRuntimeState::Idle);
    assert!(heartbeat.xray_version.is_none());
    assert!(heartbeat.endpoints.is_empty());
    assert!(heartbeat.revisions.desired_revision.is_none());
    assert_eq!(heartbeat.telemetry_cursor.get(), 0);

    assert_eq!(captured[1].method, Method::GET);
    assert_eq!(
        captured[1].path_and_query,
        format!("/v1/nodes/{}/desired?afterRevision=0", registration.node)
    );
    assert!(captured[1].body.is_empty());

    let heartbeat_auth = verify_captured(&captured[0], &public_key, registration);
    let desired_auth = verify_captured(&captured[1], &public_key, registration);
    assert_ne!(heartbeat_auth.nonce(), desired_auth.nonce());
    let transient_auth_values = [
        heartbeat_auth.nonce().as_str().to_owned(),
        heartbeat_auth.signature().as_str().to_owned(),
        desired_auth.nonce().as_str().to_owned(),
        desired_auth.signature().as_str().to_owned(),
    ];

    let changed_body =
        NodeRequestSigningInput::from_body("POST", &captured[0].path_and_query, b"{}").unwrap();
    assert!(verify_node_request_signature(
        &public_key,
        &heartbeat_auth,
        &changed_body,
        registration.controller_instance
    )
    .is_err());
    let changed_path = NodeRequestSigningInput::from_body(
        "POST",
        &captured[0].path_and_query.replace("heartbeat", "desired"),
        &captured[0].body,
    )
    .unwrap();
    assert!(verify_node_request_signature(
        &public_key,
        &heartbeat_auth,
        &changed_path,
        registration.controller_instance
    )
    .is_err());
    let changed_query = NodeRequestSigningInput::from_body(
        "GET",
        &captured[1]
            .path_and_query
            .replace("afterRevision=0", "afterRevision=1"),
        &captured[1].body,
    )
    .unwrap();
    assert!(verify_node_request_signature(
        &public_key,
        &desired_auth,
        &changed_query,
        registration.controller_instance
    )
    .is_err());

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let persisted: (Option<i64>, Option<i64>, i64, i64) = connection
        .query_row(
            "SELECT last_heartbeat_at, last_sync_at, desired_revision_cursor,
                    heartbeat_generation
             FROM control_sync_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(persisted.0.is_some());
    assert!(persisted.1.is_some());
    assert_eq!(persisted.2, 0);
    assert_eq!(persisted.3, 1);
    drop(connection);

    let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
    for value in transient_auth_values {
        assert!(!contains_bytes(&database, value.as_bytes()));
    }
    let identity_seed = fs::read(data_dir.join("identity.ed25519.seed")).unwrap();
    assert!(!contains_bytes(&database, &identity_seed));
}

#[tokio::test]
async fn signed_controller_status_is_verified_persisted_and_retained_across_legacy_204() {
    let controller = MockController::start(ResponseMode::NoDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let response = signed_controller_status(&data_dir, registration, 1);
    controller.set_heartbeat_status(response.clone());

    let synced = sync_once(&data_dir).await.unwrap();
    assert_eq!(synced.controller_status, Some(response.document.clone()));
    assert!(synced.last_heartbeat_at.is_some());
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let stored: (i64, String, String, String) = connection
        .query_row(
            "SELECT heartbeat_generation, node_id, controller_instance_id, signing_key_id
             FROM controller_status_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored.0, 1);
    assert_eq!(stored.1, registration.node.to_string());
    assert_eq!(stored.2, registration.controller_instance.to_string());
    assert_eq!(stored.3, response.document.signing_key_id.to_string());
    drop(connection);

    let reloaded = status(&data_dir).unwrap();
    assert_eq!(reloaded.controller_status, Some(response.document.clone()));

    controller.clear_heartbeat_status();
    let legacy = sync_once(&data_dir).await.unwrap();
    assert_eq!(legacy.controller_status, Some(response.document));
}

#[tokio::test]
async fn controller_status_rejects_wrong_binding_key_identity_and_signature() {
    assert_rejected_controller_status(
        |status| {
            status.document.heartbeat_generation = SequenceNumber::new(2).unwrap();
        },
        true,
        "document failed validation",
    )
    .await;
    assert_rejected_controller_status(
        |status| status.document.node_id = NodeId::new(),
        true,
        "document failed validation",
    )
    .await;
    assert_rejected_controller_status(
        |status| status.document.controller_instance_id = ControllerInstanceId::new(),
        true,
        "document failed validation",
    )
    .await;
    assert_rejected_controller_status(
        |status| status.document.signing_key_id = SigningKeyId::new(),
        true,
        "signing key identity is invalid",
    )
    .await;
    assert_rejected_controller_status(
        |status| status.document.lifecycle = NodeLifecycleState::Pending,
        false,
        "signature is invalid",
    )
    .await;
}

#[tokio::test]
async fn tampered_persisted_controller_status_fails_closed() {
    let controller = MockController::start(ResponseMode::NoDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    controller.set_heartbeat_status(signed_controller_status(&data_dir, registration, 1));
    sync_once(&data_dir).await.unwrap();

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE controller_status_state SET envelope_json = '{}' WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(connection);
    let error = status(&data_dir).unwrap_err();
    assert!(error
        .to_string()
        .contains("controller status artifact digest is invalid"));
}

fn verify_captured(
    request: &CapturedRequest,
    public_key: &Ed25519PublicKey,
    registration: Registration,
) -> NodeRequestAuthHeaders {
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .to_str()
            .unwrap()
    };
    let auth = NodeRequestAuthHeaders::parse(
        header("X-Node-Id"),
        header("X-Node-Key-Id"),
        header("X-Node-Timestamp"),
        header("X-Node-Nonce"),
        header("X-Node-Signature"),
    )
    .unwrap();
    assert_eq!(auth.node_id(), registration.node);
    assert_eq!(auth.key_id(), registration.key);
    let input = NodeRequestSigningInput::from_body(
        request.method.as_str(),
        &request.path_and_query,
        &request.body,
    )
    .unwrap();
    verify_node_request_signature(public_key, &auth, &input, registration.controller_instance)
        .unwrap();
    auth
}

#[tokio::test]
async fn unenrolled_host_is_rejected_before_network_access() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    initialize(&data_dir, "http://127.0.0.1:9").unwrap();

    let error = sync_once(&data_dir).await.unwrap_err();
    assert!(error.to_string().contains("not enrolled"));
}

#[tokio::test]
async fn controller_error_body_is_redacted() {
    let controller = MockController::start(ResponseMode::RejectHeartbeat).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    install_registration(&data_dir, &controller.origin);

    let error = sync_once(&data_dir).await.unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("authentication_failed"));
    assert!(!rendered.contains(SECRET_RESPONSE_TEXT));
    sync_once(&data_dir).await.unwrap_err();
    let generations: Vec<i64> = controller
        .captured()
        .iter()
        .map(|request| {
            serde_json::from_slice::<NodeHeartbeat>(&request.body)
                .unwrap()
                .heartbeat_generation
                .get()
        })
        .collect();
    assert_eq!(generations, vec![1, 2]);
    let current = status(&data_dir).unwrap();
    assert!(current.last_heartbeat_at.is_none());
    assert!(current.last_sync_at.is_none());
}

#[tokio::test]
async fn unverified_desired_body_is_rejected_without_advancing_sync() {
    let controller = MockController::start(ResponseMode::UnverifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    install_registration(&data_dir, &controller.origin);

    let error = sync_once(&data_dir).await.unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("invalid desired-state JSON"));
    assert!(!rendered.contains(SECRET_RESPONSE_TEXT));
    let current = status(&data_dir).unwrap();
    assert!(current.last_heartbeat_at.is_some());
    assert!(current.last_sync_at.is_none());
    assert_eq!(current.desired_revision_cursor, 0);
}

#[tokio::test]
async fn verified_desired_state_is_persisted_reported_and_not_fetched_twice() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let public_key = status(&data_dir).unwrap().identity_public_key;
    let desired = signed_desired(&data_dir, registration, 1);
    controller.set_desired(desired.clone());

    let synced = sync_once(&data_dir).await.unwrap();
    assert_eq!(synced.desired_revision_cursor, 1);
    assert!(synced.last_sync_at.is_some());

    let captured = controller.captured();
    assert_eq!(captured.len(), 3);
    assert_eq!(captured[0].method, Method::POST);
    assert_eq!(captured[1].method, Method::GET);
    assert_eq!(captured[2].method, Method::PUT);
    assert_eq!(
        captured[2].path_and_query,
        format!("/v1/nodes/{}/revisions/1/result", registration.node)
    );
    let report: RevisionResult = serde_json::from_slice(&captured[2].body).unwrap();
    assert_eq!(report.state, RevisionResultState::Received);
    for request in &captured {
        verify_captured(request, &public_key, registration);
    }

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let artifact: (String, String, String) = connection
        .query_row(
            "SELECT envelope_json, envelope_digest, transcript_digest
             FROM desired_state_artifacts WHERE revision = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let stored: SignedDesiredState = serde_json::from_str(&artifact.0).unwrap();
    assert_eq!(stored, desired);
    assert!(artifact.1.starts_with("sha256:"));
    assert!(artifact.2.starts_with("sha256:"));
    let reported_at: Option<i64> = connection
        .query_row(
            "SELECT reported_at FROM local_revision_results
             WHERE revision = 1 AND state = 'received'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(reported_at.is_some());
    assert!(connection
        .execute(
            "UPDATE desired_state_artifacts SET received_at = 0 WHERE revision = 1",
            [],
        )
        .is_err());
    drop(connection);

    sync_once(&data_dir).await.unwrap();
    let captured = controller.captured();
    assert_eq!(captured.len(), 5);
    assert_eq!(captured[3].method, Method::POST);
    assert_eq!(captured[4].method, Method::GET);
    assert!(captured[4].path_and_query.ends_with("afterRevision=1"));
}

#[tokio::test]
async fn legacy_version_one_desired_state_remains_acceptable() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    controller.set_desired(signed_desired_for_schema(&data_dir, registration, 1, 1));

    let synced = sync_once(&data_dir).await.unwrap();

    assert_eq!(synced.desired_revision_cursor, 1);
    let stored: String = Connection::open(data_dir.join("node-host.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT envelope_json FROM desired_state_artifacts WHERE revision = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let stored: SignedDesiredState = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored.document.schema_version, 1);
    assert_eq!(stored.document.xray.public_port, None);
}

#[cfg(unix)]
#[tokio::test]
async fn configured_runtime_validates_and_persists_an_immutable_candidate() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let public_key = status(&data_dir).unwrap().identity_public_key;
    let fake = FakeXray::new(FakeConfigMode::Valid);
    configure_xray(&data_dir, &fake.path, &fake.digest, false)
        .await
        .unwrap();
    controller.set_desired(signed_desired(&data_dir, registration, 1));

    let synced = sync_once(&data_dir).await.unwrap();
    assert_eq!(synced.desired_revision_cursor, 1);
    let captured = controller.captured();
    assert_eq!(captured.len(), 4);
    assert_eq!(captured[2].method, Method::PUT);
    assert_eq!(captured[3].method, Method::PUT);
    let received: RevisionResult = serde_json::from_slice(&captured[2].body).unwrap();
    let validated: RevisionResult = serde_json::from_slice(&captured[3].body).unwrap();
    assert_eq!(received.state, RevisionResultState::Received);
    assert_eq!(validated.state, RevisionResultState::Validated);
    assert!(validated.config_digest.is_some());
    for request in &captured {
        verify_captured(request, &public_key, registration);
    }

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let stored: (String, String, String) = connection
        .query_row(
            "SELECT relative_path, config_digest, binary_digest
             FROM rendered_xray_configs WHERE revision = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored.0, "configs/revision-1.json");
    assert_eq!(stored.1, validated.config_digest.unwrap().as_str());
    assert_eq!(stored.2, fake.digest);
    assert!(connection
        .execute(
            "UPDATE rendered_xray_configs SET validated_at = 0 WHERE revision = 1",
            [],
        )
        .is_err());
    drop(connection);

    let config_path = data_dir.join(&stored.0);
    let mode = fs::metadata(&config_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let directory_mode = fs::metadata(data_dir.join("configs"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(directory_mode, 0o700);
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(config["inbounds"][0]["port"], 10_443);
    assert_eq!(
        config["inbounds"][0]["settings"]["users"][0]["id"],
        "2f55c837-7be6-4752-b58a-a7f51401bd89"
    );

    sync_once(&data_dir).await.unwrap();
    let captured = controller.captured();
    assert_eq!(captured.len(), 6);
    let heartbeat: NodeHeartbeat = serde_json::from_slice(&captured[4].body).unwrap();
    assert_eq!(heartbeat.xray_version.as_deref(), Some("Xray 25.7.1"));
    assert_eq!(heartbeat.revisions.desired_revision.unwrap().get(), 1);
    assert_eq!(heartbeat.revisions.received_revision.unwrap().get(), 1);
    assert_eq!(heartbeat.revisions.validated_revision.unwrap().get(), 1);
    assert!(heartbeat.revisions.applied_revision.is_none());

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE local_revision_results SET reported_at = NULL
             WHERE revision = 1 AND state = 'validated'",
            [],
        )
        .unwrap();
    drop(connection);
    fs::write(&config_path, b"{}\n").unwrap();
    controller.clear_captured();

    let error = sync_once(&data_dir).await.unwrap_err();
    assert!(format!("{error:#}").contains("config digest is invalid"));
    assert!(controller.captured().is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn xray_config_rejection_is_terminal_but_redacted() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let fake = FakeXray::new(FakeConfigMode::Reject);
    configure_xray(&data_dir, &fake.path, &fake.digest, false)
        .await
        .unwrap();
    controller.set_desired(signed_desired(&data_dir, registration, 1));

    let synced = sync_once(&data_dir).await.unwrap();
    assert!(synced.last_sync_at.is_some());
    let captured = controller.captured();
    assert_eq!(captured.len(), 4);
    let rejected: RevisionResult = serde_json::from_slice(&captured[3].body).unwrap();
    assert_eq!(rejected.state, RevisionResultState::Rejected);
    assert_eq!(rejected.error_code, Some(ErrorCode::ValidationFailed));
    assert!(rejected.config_digest.is_none());
    assert!(!String::from_utf8_lossy(&captured[3].body).contains(SECRET_XRAY_OUTPUT));

    let database_path = data_dir.join("node-host.sqlite3");
    let connection = Connection::open(&database_path).unwrap();
    let rendered_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM rendered_xray_configs", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rendered_count, 0);
    drop(connection);
    assert!(!contains_bytes(
        &fs::read(database_path).unwrap(),
        SECRET_XRAY_OUTPUT.as_bytes()
    ));
    assert!(!data_dir.join("configs").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn transient_binary_failure_stays_received_and_recovers_before_heartbeat() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let fake = FakeXray::new(FakeConfigMode::Valid);
    configure_xray(&data_dir, &fake.path, &fake.digest, false)
        .await
        .unwrap();
    fake.tamper();
    controller.set_desired(signed_desired(&data_dir, registration, 1));

    let error = sync_once(&data_dir).await.unwrap_err();
    assert!(format!("{error:#}").contains("checksum mismatch"));
    let captured = controller.captured();
    assert_eq!(captured.len(), 3);
    let received: RevisionResult = serde_json::from_slice(&captured[2].body).unwrap();
    assert_eq!(received.state, RevisionResultState::Received);
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let states: Vec<String> = connection
        .prepare("SELECT state FROM local_revision_results ORDER BY state")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(states, vec!["received"]);
    drop(connection);

    fake.restore();
    let recovered = sync_once(&data_dir).await.unwrap();
    assert!(recovered.last_sync_at.is_some());
    let captured = controller.captured();
    assert_eq!(captured.len(), 6);
    assert_eq!(captured[3].method, Method::PUT);
    let validated: RevisionResult = serde_json::from_slice(&captured[3].body).unwrap();
    assert_eq!(validated.state, RevisionResultState::Validated);
    assert!(captured[4].path_and_query.ends_with("/heartbeat"));
    let heartbeat: NodeHeartbeat = serde_json::from_slice(&captured[4].body).unwrap();
    assert_eq!(heartbeat.revisions.validated_revision.unwrap().get(), 1);
    assert!(captured[5].path_and_query.ends_with("afterRevision=1"));
}

#[tokio::test]
async fn tampered_desired_state_never_advances_the_durable_cursor() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    let mut desired = signed_desired(&data_dir, registration, 1);
    desired.document.xray.target = "tampered.example:443".to_string();
    controller.set_desired(desired);

    let error = sync_once(&data_dir).await.unwrap_err();
    assert!(format!("{error:#}").contains("signature is invalid"));
    let current = status(&data_dir).unwrap();
    assert_eq!(current.desired_revision_cursor, 0);
    assert!(current.last_heartbeat_at.is_some());
    assert!(current.last_sync_at.is_none());
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let artifact_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM desired_state_artifacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(artifact_count, 0);
}

#[tokio::test]
async fn failed_result_report_is_retried_before_the_next_heartbeat() {
    let controller = MockController::start(ResponseMode::VerifiedDesiredState).await;
    controller.reject_revision_results(true);
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    let registration = install_registration(&data_dir, &controller.origin);
    controller.set_desired(signed_desired(&data_dir, registration, 1));

    let first_error = sync_once(&data_dir).await.unwrap_err();
    let rendered = format!("{first_error:#}");
    assert!(rendered.contains("service_unavailable"));
    assert!(!rendered.contains(SECRET_RESPONSE_TEXT));
    let interrupted = status(&data_dir).unwrap();
    assert_eq!(interrupted.desired_revision_cursor, 1);
    assert!(interrupted.last_sync_at.is_none());

    controller.reject_revision_results(false);
    sync_once(&data_dir).await.unwrap();
    let captured = controller.captured();
    assert_eq!(captured.len(), 6);
    assert_eq!(captured[3].method, Method::PUT);
    assert_eq!(captured[4].method, Method::POST);
    assert_eq!(captured[5].method, Method::GET);
    assert!(captured[5].path_and_query.ends_with("afterRevision=1"));

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).unwrap();
    let reported_at: Option<i64> = connection
        .query_row(
            "SELECT reported_at FROM local_revision_results
             WHERE revision = 1 AND state = 'received'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(reported_at.is_some());
}

#[tokio::test]
async fn service_loop_repeats_sync_and_releases_the_data_lock_on_shutdown() {
    let controller = MockController::start(ResponseMode::NoDesiredState).await;
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    install_registration(&data_dir, &controller.origin);
    let shutdown_requests = Arc::clone(&controller.requests);

    let service = async {
        run_until(
            &data_dir,
            SyncLoopOptions {
                success_interval: StdDuration::from_millis(10),
                initial_backoff: StdDuration::from_millis(5),
                max_backoff: StdDuration::from_millis(20),
            },
            async move {
                tokio::time::timeout(StdDuration::from_millis(500), async {
                    loop {
                        if shutdown_requests.lock().unwrap().len() >= 4 {
                            break;
                        }
                        tokio::time::sleep(StdDuration::from_millis(5)).await;
                    }
                })
                .await
                .expect("service did not complete two sync cycles");
                Ok(())
            },
        )
        .await
    };
    let observe_lock = async {
        #[cfg(target_os = "macos")]
        {
            let mut observed_local_status = false;
            for _ in 0..40 {
                if let Ok(local) = query_local_service_status(&data_dir).await {
                    assert_eq!(local.runtime_state, NodeRuntimeState::Idle);
                    assert!(!local.xray_configured);
                    observed_local_status = true;
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(5)).await;
            }
            assert!(observed_local_status);
        }
        let mut observed_lifetime_lock = false;
        for _ in 0..20 {
            if status(&data_dir).is_err_and(|error| error.to_string().contains("already in use")) {
                observed_lifetime_lock = true;
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(observed_lifetime_lock);
    };
    let (service_result, ()) = tokio::join!(service, observe_lock);
    service_result.unwrap();

    let captured = controller.captured();
    assert!(captured.len() >= 4);
    let generations: Vec<i64> = captured
        .iter()
        .filter(|request| request.path_and_query.ends_with("/heartbeat"))
        .map(|request| {
            serde_json::from_slice::<NodeHeartbeat>(&request.body)
                .unwrap()
                .heartbeat_generation
                .get()
        })
        .collect();
    assert!(generations.len() >= 2);
    assert!(generations.windows(2).all(|pair| pair[0] < pair[1]));
    status(&data_dir).expect("shutdown must release the exclusive data-directory lock");
    #[cfg(target_os = "macos")]
    assert!(query_local_service_status(&data_dir).await.is_err());
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
