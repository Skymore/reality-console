use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature};
use control_protocol::desired::desired_state_transcript;
use control_protocol::id::{
    ControllerInstanceId, CredentialId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, RequestId,
    Revision, SigningKeyId, Timestamp, UserId,
};
use control_protocol::node::{
    DesiredStateDocument, DesiredUser, DesiredXrayState, NodeHeartbeat, NodeRuntimeState,
    RevisionResult, RevisionResultState, SignedDesiredState,
};
use control_protocol::request_auth::{
    verify_node_request_signature, NodeRequestAuthHeaders, NodeRequestSigningInput,
};
use control_protocol::secret::Secret;
use ed25519_dalek::{Signer as _, SigningKey};
use node_host::{initialize, status, sync_once, EnrollmentState};
use rusqlite::{params, Connection};
use serde_json::json;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

const SECRET_RESPONSE_TEXT: &str = "controller-private-debug-secret";

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
    reject_revision_results: Arc<AtomicBool>,
}

struct MockController {
    origin: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    desired: Arc<Mutex<Option<SignedDesiredState>>>,
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
        let reject_revision_results = Arc::new(AtomicBool::new(false));
        let state = MockState {
            mode,
            requests: Arc::clone(&requests),
            desired: Arc::clone(&desired),
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
            reject_revision_results,
            task,
        }
    }

    fn captured(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn set_desired(&self, desired: SignedDesiredState) {
        *self.desired.lock().unwrap() = Some(desired);
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
        return match state.mode {
            ResponseMode::RejectHeartbeat => (
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
                .into_response(),
            _ => StatusCode::NO_CONTENT.into_response(),
        };
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
    let signing_seed: [u8; 32] = fs::read(data_dir.join("identity.ed25519.seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let document = DesiredStateDocument {
        schema_version: 1,
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
            listen_port: 443,
            server_names: vec!["www.microsoft.com".to_string()],
            target: "www.microsoft.com:443".to_string(),
        },
        signing_key_id: SigningKeyId::new(),
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
    assert_eq!(synced.desired_revision_cursor, 0);
    assert_eq!(synced.schema_version, 4);

    let captured = controller.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].method, Method::POST);
    assert_eq!(
        captured[0].path_and_query,
        format!("/v1/nodes/{}/heartbeat", registration.node)
    );
    let heartbeat: NodeHeartbeat = serde_json::from_slice(&captured[0].body).unwrap();
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
    let persisted: (Option<i64>, Option<i64>, i64) = connection
        .query_row(
            "SELECT last_heartbeat_at, last_sync_at, desired_revision_cursor
             FROM control_sync_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(persisted.0.is_some());
    assert!(persisted.1.is_some());
    assert_eq!(persisted.2, 0);
    drop(connection);

    let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
    for value in transient_auth_values {
        assert!(!contains_bytes(&database, value.as_bytes()));
    }
    let identity_seed = fs::read(data_dir.join("identity.ed25519.seed")).unwrap();
    assert!(!contains_bytes(&database, &identity_seed));
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

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
