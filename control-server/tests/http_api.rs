use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{
    Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest, X25519PublicKey,
};
use control_protocol::desired::verify_desired_state_signature;
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, EnrollmentInvitation,
};
use control_protocol::error::ErrorCode;
use control_protocol::id::{
    ControllerInstanceId, CredentialId, NodeId, NodeKeyId, Revision, SequenceNumber, Timestamp,
    UserId,
};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EndpointMode, EndpointStatus,
    EnrollNodeRequest, EnrollNodeResponse, NodeCapability, NodeEndpointStatus, NodeHeartbeat,
    NodeRuntimeState, ProviderConsent, RevisionProgress, RevisionResult, RevisionResultState,
    SignedDesiredState,
};
use control_protocol::request_auth::NodeRequestSigningInput;
use control_server::{build_router, AppState, Database, ServiceConfig};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use futures_util::stream;
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore as _};
use serde_json::Value;
use sha2::Digest as _;
use std::convert::Infallible;
use std::path::PathBuf;
use std::str::FromStr as _;
use tempfile::TempDir;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "integration-bootstrap-token-with-enough-entropy";

struct TestApp {
    temp: TempDir,
    router: axum::Router,
    controller_public_key: Ed25519PublicKey,
}

impl TestApp {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        Self::from_temp(temp)
    }

    fn from_temp(temp: TempDir) -> Self {
        let config = ServiceConfig::for_test(temp.path().join("control.sqlite3"), TOKEN).unwrap();
        let database = Database::open(&config.database_path, &config.network_display_name).unwrap();
        let controller_public_key = database.controller_identity().public_key();
        let state = AppState::new(
            database,
            config.bootstrap_token,
            config.controller_origin,
            config.request_timeout,
        );
        Self {
            temp,
            router: build_router(state),
            controller_public_key,
        }
    }

    fn restart(self) -> Self {
        let Self {
            temp,
            router,
            controller_public_key: _,
        } = self;
        drop(router);
        Self::from_temp(temp)
    }

    fn database_path(&self) -> PathBuf {
        self.temp.path().join("control.sqlite3")
    }
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_invitation(app: &TestApp, expires_in_seconds: u32) -> CreateNodeInvitationResponse {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CreateNodeInvitationRequest {
                        display_name: "Friend host".to_string(),
                        expires_in_seconds,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn signed_enrollment(invitation: &CreateNodeInvitationResponse) -> (EnrollNodeRequest, Vec<u8>) {
    let (request, transcript, _) = signed_enrollment_with_key(invitation);
    (request, transcript)
}

fn signed_enrollment_with_key(
    invitation: &CreateNodeInvitationResponse,
) -> (EnrollNodeRequest, Vec<u8>, SigningKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_public_key =
        Ed25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()))
            .unwrap();
    let mut encryption_key_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut encryption_key_bytes);
    let encryption_public_key =
        X25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(encryption_key_bytes)).unwrap();
    let nonce = Nonce::from_str(&URL_SAFE_NO_PAD.encode([7_u8; 32])).unwrap();
    let mut request = EnrollNodeRequest {
        invitation_secret: invitation.invitation_secret.clone(),
        agent_version: "0.1.0".to_string(),
        platform: "macos-arm64".to_string(),
        display_name: "Living room Mac".to_string(),
        capabilities: vec![NodeCapability::Xray, NodeCapability::DirectTcp],
        identity_public_key,
        encryption_public_key,
        nonce,
        proof: Ed25519Signature::from_str(&URL_SAFE_NO_PAD.encode([0_u8; 64])).unwrap(),
        provider_consent: ProviderConsent {
            policy_version: "2026-07-11".to_string(),
            host_owner_consented: true,
            exit_ip_disclosure_accepted: true,
            accepted_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
        },
    };
    let invitation_context = EnrollmentInvitation {
        invitation_id: invitation.invitation_id,
        purpose: invitation.purpose,
        expires_at: invitation.expires_at,
        controller_origin: &invitation.controller_origin,
        controller_fingerprint: &invitation.controller_fingerprint,
    };
    let transcript = enrollment_request_transcript(&invitation_context, &request).unwrap();
    request.proof = Ed25519Signature::from_str(
        &URL_SAFE_NO_PAD.encode(signing_key.sign(&transcript).to_bytes()),
    )
    .unwrap();
    (request, transcript, signing_key)
}

async fn enroll(app: &TestApp, request: &EnrollNodeRequest) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post("/v1/nodes/enroll")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn admin_node_action(
    app: &TestApp,
    node_id: NodeId,
    action: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/nodes/{node_id}/{action}"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn admin_nodes(app: &TestApp) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::get("/v1/admin/nodes")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn assert_revoked_state_and_lifecycle_audit(app: &TestApp, node_id: NodeId) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let (status, live_credentials): (String, i64) = connection
        .query_row(
            "SELECT n.status,
                    (SELECT COUNT(*) FROM node_auth_credentials AS c
                     WHERE c.node_id = n.node_id AND c.revoked_at IS NULL)
             FROM nodes AS n WHERE n.node_id = ?1",
            [node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "revoked");
    assert_eq!(live_credentials, 0);

    let mut statement = connection
        .prepare(
            "SELECT actor_type, event_type, outcome, details_json
             FROM audit_events
             WHERE target_type = 'node' AND target_id = ?1
               AND event_type IN ('node.approved', 'node.disabled', 'node.revoked')
             ORDER BY event_id",
        )
        .unwrap();
    let events: Vec<(String, String, String, Value)> = statement
        .query_map([node_id.to_string()], |row| {
            let details: String = row.get(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                serde_json::from_str(&details).unwrap(),
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(events.len(), 7);
    assert!(events.iter().all(|event| event.0 == "admin"));
    assert_eq!(
        (events[0].1.as_str(), events[0].2.as_str()),
        ("node.approved", "success")
    );
    assert_eq!(events[0].3["idempotent"], false);
    assert_eq!(events[1].3["idempotent"], true);
    assert_eq!(
        (events[2].1.as_str(), events[2].2.as_str()),
        ("node.disabled", "success")
    );
    assert_eq!(events[3].3["idempotent"], true);
    assert_eq!(
        (events[4].1.as_str(), events[4].2.as_str()),
        ("node.approved", "rejected")
    );
    assert_eq!(events[4].3["reason"], "invalid-state-transition");
    assert_eq!(
        (events[5].1.as_str(), events[5].2.as_str()),
        ("node.revoked", "success")
    );
    assert_eq!(events[5].3["credentialsRevoked"], 1);
    assert_eq!(events[6].3["idempotent"], true);
}

struct SignedNode {
    node_id: NodeId,
    key_id: NodeKeyId,
    controller_instance_id: ControllerInstanceId,
    signing_key: SigningKey,
}

async fn enroll_signed_node(app: &TestApp) -> SignedNode {
    let invitation = create_invitation(app, 900).await;
    let (request, _, signing_key) = signed_enrollment_with_key(&invitation);
    let response = enroll(app, &request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let enrolled: EnrollNodeResponse = serde_json::from_value(json(response).await).unwrap();
    SignedNode {
        node_id: enrolled.node_id,
        key_id: enrolled.credential.key_id,
        controller_instance_id: enrolled.controller_instance_id,
        signing_key,
    }
}

fn signed_node_request(
    node: &SignedNode,
    method: &str,
    path_and_query: &str,
    body: Vec<u8>,
    timestamp: Timestamp,
    nonce: &Nonce,
) -> Request<Body> {
    let input = NodeRequestSigningInput::from_body(method, path_and_query, &body).unwrap();
    let transcript = input
        .transcript(timestamp, nonce, node.controller_instance_id)
        .unwrap();
    let signature = URL_SAFE_NO_PAD.encode(node.signing_key.sign(&transcript).to_bytes());
    Request::builder()
        .method(method)
        .uri(path_and_query)
        .header("x-node-id", node.node_id.to_string())
        .header("x-node-key-id", node.key_id.to_string())
        .header("x-node-timestamp", timestamp.to_string())
        .header("x-node-nonce", nonce.as_str())
        .header("x-node-signature", signature)
        .body(Body::from(body))
        .unwrap()
}

fn nonce(byte: u8) -> Nonce {
    Nonce::from_str(&URL_SAFE_NO_PAD.encode([byte; 32])).unwrap()
}

fn heartbeat() -> NodeHeartbeat {
    NodeHeartbeat {
        agent_version: "0.2.0".to_string(),
        xray_version: Some("26.7.11".to_string()),
        state: NodeRuntimeState::Serving,
        revisions: RevisionProgress {
            desired_revision: None,
            received_revision: None,
            validated_revision: None,
            applied_revision: None,
        },
        provider_paused: false,
        endpoints: vec![NodeEndpointStatus {
            mode: EndpointMode::Direct,
            address: "node.example.test".to_string(),
            port: 443,
            status: EndpointStatus::Verified,
        }],
        telemetry_cursor: SequenceNumber::new(9).unwrap(),
    }
}

fn desired_state_body() -> Value {
    serde_json::json!({
        "minAgentVersion": "0.2.0",
        "users": [
            {
                "userId": UserId::new(),
                "credentialId": CredentialId::new(),
                "vlessUuid": Uuid::new_v4(),
                "enabled": true
            },
            {
                "userId": UserId::new(),
                "credentialId": CredentialId::new(),
                "vlessUuid": Uuid::new_v4(),
                "enabled": false
            }
        ],
        "xray": {
            "listenPort": 10443,
            "publicPort": 443,
            "serverNames": ["z.example.test", "a.example.test"],
            "target": "a.example.test:443"
        }
    })
}

async fn publish_desired(app: &TestApp, node_id: NodeId, body: &Value) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/nodes/{node_id}/desired-state"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn approve_and_publish(app: &TestApp, node: &SignedNode, body: &Value) -> SignedDesiredState {
    assert_eq!(
        admin_node_action(app, node.node_id, "approve")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let response = publish_desired(app, node.node_id, body).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    serde_json::from_value(json(response).await).unwrap()
}

async fn fetch_desired(
    app: &TestApp,
    node: &SignedNode,
    after_revision: i64,
    nonce_byte: u8,
) -> axum::response::Response {
    let path = format!(
        "/v1/nodes/{}/desired?afterRevision={after_revision}",
        node.node_id
    );
    let request = signed_node_request(
        node,
        "GET",
        &path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(nonce_byte),
    );
    app.router.clone().oneshot(request).await.unwrap()
}

async fn report_result(
    app: &TestApp,
    node: &SignedNode,
    revision: Revision,
    result: &RevisionResult,
    nonce_byte: u8,
) -> axum::response::Response {
    let path = format!(
        "/v1/nodes/{}/revisions/{}/result",
        node.node_id,
        revision.get()
    );
    let body = serde_json::to_vec(result).unwrap();
    let request = signed_node_request(
        node,
        "PUT",
        &path,
        body,
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(nonce_byte),
    );
    app.router.clone().oneshot(request).await.unwrap()
}

async fn post_heartbeat(
    app: &TestApp,
    node: &SignedNode,
    heartbeat: &NodeHeartbeat,
    nonce_byte: u8,
) -> axum::response::Response {
    let path = format!("/v1/nodes/{}/heartbeat", node.node_id);
    let request = signed_node_request(
        node,
        "POST",
        &path,
        serde_json::to_vec(heartbeat).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(nonce_byte),
    );
    app.router.clone().oneshot(request).await.unwrap()
}

fn assert_revision_journal_progress(app: &TestApp, node_id: NodeId) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let progress: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT desired_revision, reported_desired_revision, received_revision,
                    validated_revision, applied_revision
             FROM nodes WHERE node_id = ?1",
            [node_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(progress, (1, 1, 1, 1, 1));
    let journal_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM node_revision_results WHERE node_id = ?1",
            [node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(journal_count, 3);
    assert!(connection
        .execute(
            "UPDATE node_revision_results SET created_at = created_at + 1",
            [],
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM node_revision_results", [])
        .is_err());
}

fn assert_cached_progress(
    app: &TestApp,
    node_id: NodeId,
    expected: (i64, i64, i64, Option<i64>, Option<i64>),
) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let progress = connection
        .query_row(
            "SELECT desired_revision, reported_desired_revision, received_revision,
                    validated_revision, applied_revision
             FROM nodes WHERE node_id = ?1",
            [node_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(progress, expected);
}

fn revision_result(
    state: RevisionResultState,
    digest_byte: u8,
    rollback_revision: Option<Revision>,
) -> RevisionResult {
    let has_digest = matches!(
        state,
        RevisionResultState::Validated
            | RevisionResultState::Applied
            | RevisionResultState::RolledBack
    );
    let has_error = matches!(
        state,
        RevisionResultState::Rejected | RevisionResultState::RolledBack
    );
    RevisionResult {
        state,
        config_digest: has_digest.then(|| Sha256Digest::from_bytes([digest_byte; 32])),
        started_at: "2026-07-11T20:00:01Z".parse().unwrap(),
        completed_at: "2026-07-11T20:00:02Z".parse().unwrap(),
        error_code: has_error.then_some(ErrorCode::ValidationFailed),
        rollback_revision,
    }
}

async fn report_applied_revision(
    app: &TestApp,
    node: &SignedNode,
    revision: Revision,
    digest_byte: u8,
    nonce_bytes: [u8; 3],
) {
    for (state, nonce_byte) in [
        (RevisionResultState::Received, nonce_bytes[0]),
        (RevisionResultState::Validated, nonce_bytes[1]),
        (RevisionResultState::Applied, nonce_bytes[2]),
    ] {
        let result = revision_result(state, digest_byte, None);
        assert_eq!(
            report_result(app, node, revision, &result, nonce_byte)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
}

async fn approve_node(app: &TestApp, node_id: NodeId) {
    assert_eq!(
        admin_node_action(app, node_id, "approve").await.status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn health_is_public_and_has_a_request_id() {
    let app = TestApp::new();
    let response = app
        .router
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response.headers()["x-request-id"].to_str().unwrap();
    assert_eq!(Uuid::parse_str(request_id).unwrap().to_string(), request_id);
    assert_eq!(json(response).await["status"], "ok");
}

#[tokio::test]
async fn admin_route_requires_the_bootstrap_bearer() {
    let app = TestApp::new();
    let response = app
        .router
        .clone()
        .oneshot(
            Request::get("/v1/admin/network")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response_request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_string();
    let body = json(response).await;
    assert_eq!(body["error"]["code"], "authentication_failed");
    assert_eq!(body["error"]["requestId"], response_request_id);

    let authorized = app
        .router
        .oneshot(
            Request::get("/v1/admin/network")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);
    let body = json(authorized).await;
    assert_eq!(body["displayName"], "Private Network");
    assert_eq!(body["status"], "active");
    assert_eq!(body["lastRevision"], 0);
}

#[tokio::test]
async fn admin_node_list_is_complete_and_redacts_key_material() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let heartbeat_path = format!("/v1/nodes/{}/heartbeat", node.node_id);
    let heartbeat_request = signed_node_request(
        &node,
        "POST",
        &heartbeat_path,
        serde_json::to_vec(&heartbeat()).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(60),
    );
    assert_eq!(
        app.router
            .clone()
            .oneshot(heartbeat_request)
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let (identity_public_key, encryption_public_key): (String, String) = connection
        .query_row(
            "SELECT identity_public_key, encryption_public_key FROM nodes WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    drop(connection);

    let response = admin_nodes(&app).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = std::str::from_utf8(&bytes).unwrap();
    assert!(!raw.contains(&identity_public_key));
    assert!(!raw.contains(&encryption_public_key));
    assert!(!raw.contains("identityPublicKey"));
    assert!(!raw.contains("encryptionPublicKey"));

    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    let summary = &nodes[0];
    assert_eq!(summary["nodeId"], node.node_id.to_string());
    assert!(Uuid::parse_str(summary["networkId"].as_str().unwrap()).is_ok());
    assert_eq!(summary["displayName"], "Living room Mac");
    assert_eq!(summary["status"], "pending");
    assert_eq!(summary["platform"], "macos-arm64");
    assert_eq!(summary["agentVersion"], "0.2.0");
    assert_eq!(summary["xrayVersion"], "26.7.11");
    assert_eq!(
        summary["capabilities"],
        serde_json::json!(["xray", "direct-tcp"])
    );
    assert_eq!(summary["providerConsent"]["policyVersion"], "2026-07-11");
    assert_eq!(summary["providerConsent"]["hostOwnerConsented"], true);
    assert_eq!(summary["providerConsent"]["exitIpDisclosureAccepted"], true);
    assert!(summary["providerConsent"]["acceptedAt"].is_string());
    assert!(summary["lastSeenAt"].is_string());
    assert_eq!(summary["runtimeState"], "serving");
    assert_eq!(summary["providerPaused"], false);
    assert!(summary["revisions"]["desiredRevision"].is_null());
    assert!(summary["revisions"]["receivedRevision"].is_null());
    assert!(summary["revisions"]["validatedRevision"].is_null());
    assert!(summary["revisions"]["appliedRevision"].is_null());
    assert_eq!(summary["telemetryCursor"], 9);
    assert!(summary["createdAt"].is_string());
    assert!(summary["updatedAt"].is_string());
}

#[tokio::test]
async fn operator_lifecycle_is_strict_idempotent_audited_and_blocks_node_auth() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;

    assert_eq!(
        admin_node_action(&app, node.node_id, "approve")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_node_action(&app, node.node_id, "approve")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_node_action(&app, node.node_id, "disable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_node_action(&app, node.node_id, "disable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let desired_path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let disabled_request = signed_node_request(
        &node,
        "GET",
        &desired_path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(61),
    );
    let disabled_response = app.router.clone().oneshot(disabled_request).await.unwrap();
    assert_eq!(disabled_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(disabled_response).await["error"]["code"],
        "node_revoked"
    );

    let conflict = admin_node_action(&app, node.node_id, "approve").await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(json(conflict).await["error"]["code"], "conflict");

    assert_eq!(
        admin_node_action(&app, node.node_id, "revoke")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_node_action(&app, node.node_id, "revoke")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let revoked_request = signed_node_request(
        &node,
        "GET",
        &desired_path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(62),
    );
    let revoked_response = app.router.clone().oneshot(revoked_request).await.unwrap();
    assert_eq!(revoked_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(revoked_response).await["error"]["code"],
        "node_revoked"
    );

    assert_revoked_state_and_lifecycle_audit(&app, node.node_id);
}

#[tokio::test]
async fn revoke_accepts_pending_active_and_disabled_nodes() {
    let app = TestApp::new();
    let pending = enroll_signed_node(&app).await;
    let active = enroll_signed_node(&app).await;
    let disabled = enroll_signed_node(&app).await;
    assert_eq!(
        admin_node_action(&app, active.node_id, "approve")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_node_action(&app, disabled.node_id, "disable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    for node in [&pending, &active, &disabled] {
        assert_eq!(
            admin_node_action(&app, node.node_id, "revoke")
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    for node in [&pending, &active, &disabled] {
        let stored: (String, i64) = connection
            .query_row(
                "SELECT n.status,
                        (SELECT COUNT(*) FROM node_auth_credentials AS c
                         WHERE c.node_id = n.node_id AND c.revoked_at IS NULL)
                 FROM nodes AS n WHERE n.node_id = ?1",
                [node.node_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, ("revoked".to_string(), 0));
    }
}

#[tokio::test]
async fn operator_node_paths_require_known_canonical_bounded_uuids() {
    let app = TestApp::new();
    for path in [
        "/v1/admin/nodes/not-a-uuid/approve".to_string(),
        "/v1/admin/nodes/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA/approve".to_string(),
        "/v1/admin/nodes/00000000-0000-4000-8000-000000000000-extra/approve".to_string(),
        format!("/v1/admin/nodes/{}/approve", NodeId::new()),
    ] {
        let response = app
            .router
            .clone()
            .oneshot(
                Request::post(path)
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(response).await["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn echoes_only_valid_structured_request_ids() {
    let app = TestApp::new();
    let requested = Uuid::new_v4().to_string();
    let response = app
        .router
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-request-id", &requested)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["x-request-id"], requested);

    let invalid = app
        .router
        .oneshot(
            Request::get("/healthz")
                .header("x-request-id", "not-a-request-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let generated = invalid.headers()["x-request-id"].to_str().unwrap();
    assert!(Uuid::parse_str(generated).is_ok());
    assert_ne!(generated, "not-a-request-id");
}

#[tokio::test]
async fn framework_errors_use_the_stable_envelope() {
    let app = TestApp::new();
    let missing = app
        .router
        .clone()
        .oneshot(Request::get("/missing").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(missing).await["error"]["code"], "not_found");

    let wrong_method = app
        .router
        .oneshot(Request::post("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        json(wrong_method).await["error"]["code"],
        "method_not_allowed"
    );
}

#[tokio::test]
async fn rejects_declared_oversized_bodies_with_the_error_envelope() {
    let app = TestApp::new();
    let response = app
        .router
        .oneshot(
            Request::get("/healthz")
                .header(header::CONTENT_LENGTH, "65537")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(response).await["error"]["code"], "request_too_large");
}

#[tokio::test]
async fn creates_and_enrolls_with_mutually_verified_proofs() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    assert_eq!(
        invitation.invitation_secret.expose_secret().len(),
        43,
        "32 random bytes should use 43 unpadded base64url characters"
    );
    let (request, request_transcript) = signed_enrollment(&invitation);
    let response = enroll(&app, &request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let enrolled: EnrollNodeResponse = serde_json::from_slice(&bytes).unwrap();

    let response_transcript =
        enrollment_response_transcript(&request_transcript, &enrolled).unwrap();
    let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(enrolled.desired_state_signing_public_key.as_str())
        .unwrap()
        .try_into()
        .unwrap();
    let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(enrolled.proof.as_str())
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&public_bytes)
        .unwrap()
        .verify(
            &response_transcript,
            &Signature::from_bytes(&signature_bytes),
        )
        .unwrap();
}

#[tokio::test]
async fn concurrent_invitation_consumption_has_one_winner() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (first_request, _) = signed_enrollment(&invitation);
    let (second_request, _) = signed_enrollment(&invitation);

    let (first, second) = tokio::join!(enroll(&app, &first_request), enroll(&app, &second_request));
    let mut statuses = [first.status(), second.status()];
    statuses.sort_by_key(StatusCode::as_u16);
    assert_eq!(statuses, [StatusCode::CREATED, StatusCode::CONFLICT]);

    let loser = if first.status() == StatusCode::CONFLICT {
        first
    } else {
        second
    };
    assert_eq!(json(loser).await["error"]["code"], "invitation_consumed");
}

#[tokio::test]
async fn identical_enrollment_retry_recovers_the_existing_identity() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (request, _) = signed_enrollment(&invitation);

    let first = enroll(&app, &request).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first: EnrollNodeResponse = serde_json::from_value(json(first).await).unwrap();

    let retry = enroll(&app, &request).await;
    assert_eq!(retry.status(), StatusCode::OK);
    let retry: EnrollNodeResponse = serde_json::from_value(json(retry).await).unwrap();
    assert_eq!(retry.network_id, first.network_id);
    assert_eq!(retry.node_id, first.node_id);
    assert_eq!(retry.credential.key_id, first.credential.key_id);
    assert_eq!(retry.credential.expires_at, first.credential.expires_at);
}

#[tokio::test]
async fn invalid_proof_does_not_consume_invitation() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (valid, _) = signed_enrollment(&invitation);
    let mut invalid = valid.clone();
    invalid.proof = Ed25519Signature::from_str(&URL_SAFE_NO_PAD.encode([0_u8; 64])).unwrap();

    let rejected = enroll(&app, &invalid).await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(rejected).await["error"]["code"], "signature_invalid");
    assert_eq!(enroll(&app, &valid).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn provider_nonconsent_is_rejected_without_consuming_invitation() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (valid, _) = signed_enrollment(&invitation);
    let mut rejected_request = valid.clone();
    rejected_request
        .provider_consent
        .exit_ip_disclosure_accepted = false;

    let rejected = enroll(&app, &rejected_request).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(rejected).await["error"]["code"], "validation_failed");
    assert_eq!(enroll(&app, &valid).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn expired_invitation_is_rejected() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 1).await;
    let (request, _) = signed_enrollment(&invitation);
    let remaining = invitation.expires_at.as_datetime() - OffsetDateTime::now_utc();
    let wait = std::time::Duration::try_from(remaining)
        .unwrap_or(std::time::Duration::ZERO)
        .saturating_add(std::time::Duration::from_millis(50));
    tokio::time::sleep(wait).await;

    let response = enroll(&app, &request).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(json(response).await["error"]["code"], "invitation_expired");
}

#[tokio::test]
async fn invitation_and_controller_identity_survive_restart() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (request, _) = signed_enrollment(&invitation);
    let expected_public_key = app.controller_public_key.clone();
    let app = app.restart();
    assert_eq!(app.controller_public_key, expected_public_key);

    let response = enroll(&app, &request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    assert_eq!(
        body["desiredStateSigningPublicKey"],
        expected_public_key.as_str()
    );
}

#[tokio::test]
async fn invitation_lifetime_is_bounded() {
    let app = TestApp::new();
    let response = app
        .router
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::from(
                    serde_json::to_vec(&CreateNodeInvitationRequest {
                        display_name: "Too long lived".to_string(),
                        expires_in_seconds: 3_601,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["error"]["code"], "validation_failed");
}

#[tokio::test]
async fn malformed_and_chunked_oversized_json_use_stable_errors() {
    let app = TestApp::new();
    let malformed = app
        .router
        .clone()
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(malformed).await["error"]["code"], "validation_failed");

    let chunks = stream::iter([
        Ok::<_, Infallible>(Bytes::from(vec![b'a'; 40 * 1024])),
        Ok::<_, Infallible>(Bytes::from(vec![b'b'; 30 * 1024])),
    ]);
    let oversized = app
        .router
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::from_stream(chunks))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(oversized).await["error"]["code"], "request_too_large");
}

#[tokio::test]
async fn authenticated_heartbeat_persists_state_and_replaces_endpoints() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/heartbeat", node.node_id);
    let body = serde_json::to_vec(&heartbeat()).unwrap();
    let request = signed_node_request(
        &node,
        "POST",
        &path,
        body,
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(20),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let stored: (String, String, String, Option<i64>, i64, i64) = connection
        .query_row(
            "SELECT status, agent_version, xray_version, applied_revision,
                    telemetry_cursor, provider_paused
             FROM nodes WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        stored,
        (
            "pending".into(),
            "0.2.0".into(),
            "26.7.11".into(),
            None,
            9,
            0
        )
    );
    let endpoints: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM node_reported_endpoints WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(endpoints, 1);
    drop(connection);

    let mut next_heartbeat = heartbeat();
    next_heartbeat.endpoints = vec![NodeEndpointStatus {
        mode: EndpointMode::Relay,
        address: "relay.example.test".to_string(),
        port: 8443,
        status: EndpointStatus::Pending,
    }];
    let body = serde_json::to_vec(&next_heartbeat).unwrap();
    let request = signed_node_request(
        &node,
        "POST",
        &path,
        body,
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(29),
    );
    assert_eq!(
        app.router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let endpoints: Vec<(String, String, i64)> = connection
        .prepare(
            "SELECT mode, address, port FROM node_reported_endpoints
             WHERE node_id = ?1 ORDER BY address",
        )
        .unwrap()
        .query_map([node.node_id.to_string()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        endpoints,
        vec![("relay".into(), "relay.example.test".into(), 8443)]
    );
}

#[tokio::test]
async fn heartbeat_cannot_approve_a_node_or_regress_durable_progress() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/heartbeat", node.node_id);
    let initial = signed_node_request(
        &node,
        "POST",
        &path,
        serde_json::to_vec(&heartbeat()).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(34),
    );
    assert_eq!(
        app.router.clone().oneshot(initial).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let mut regressed = heartbeat();
    regressed.telemetry_cursor = SequenceNumber::new(8).unwrap();
    let request = signed_node_request(
        &node,
        "POST",
        &path,
        serde_json::to_vec(&regressed).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(35),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["error"]["code"], "state_stale");

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let stored: (String, Option<i64>, i64) = connection
        .query_row(
            "SELECT status, applied_revision, telemetry_cursor FROM nodes WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored, ("pending".to_string(), None, 9));
}

#[tokio::test]
async fn signed_request_rejects_body_and_identity_substitution() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/heartbeat", node.node_id);
    let signed = signed_node_request(
        &node,
        "POST",
        &path,
        serde_json::to_vec(&heartbeat()).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(21),
    );
    let (parts, _) = signed.into_parts();
    let substituted = Request::from_parts(parts, Body::from(b"{}".as_slice()));
    let response = app.router.clone().oneshot(substituted).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["error"]["code"], "signature_invalid");

    let desired = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let mut wrong_node = signed_node_request(
        &node,
        "GET",
        &desired,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(22),
    );
    wrong_node
        .headers_mut()
        .insert("x-node-id", NodeId::new().to_string().parse().unwrap());
    let response = app.router.clone().oneshot(wrong_node).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json(response).await["error"]["code"],
        "authentication_failed"
    );

    let mut wrong_key = signed_node_request(
        &node,
        "GET",
        &desired,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(23),
    );
    wrong_key.headers_mut().insert(
        "x-node-key-id",
        NodeKeyId::new().to_string().parse().unwrap(),
    );
    let response = app.router.clone().oneshot(wrong_key).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json(response).await["error"]["code"],
        "authentication_failed"
    );

    let signed_path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let substituted_path = format!("/v1/nodes/{}/desired?afterRevision=1", node.node_id);
    let signed = signed_node_request(
        &node,
        "GET",
        &signed_path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(30),
    );
    let (mut parts, body) = signed.into_parts();
    parts.uri = substituted_path.parse().unwrap();
    let response = app
        .router
        .clone()
        .oneshot(Request::from_parts(parts, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["error"]["code"], "signature_invalid");
}

#[tokio::test]
async fn expired_and_revoked_node_keys_are_rejected() {
    let app = TestApp::new();
    let expired = enroll_signed_node(&app).await;
    let revoked = enroll_signed_node(&app).await;
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE node_auth_credentials SET expires_at = 0 WHERE node_credential_id = ?1",
            [expired.key_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE node_auth_credentials SET revoked_at = 1 WHERE node_credential_id = ?1",
            [revoked.key_id.to_string()],
        )
        .unwrap();
    drop(connection);

    for (node, expected_status, expected_code, nonce_byte) in [
        (
            &expired,
            StatusCode::UNAUTHORIZED,
            "authentication_failed",
            24,
        ),
        (&revoked, StatusCode::FORBIDDEN, "node_revoked", 25),
    ] {
        let path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
        let request = signed_node_request(
            node,
            "GET",
            &path,
            Vec::new(),
            Timestamp::from_datetime(OffsetDateTime::now_utc()),
            &nonce(nonce_byte),
        );
        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(json(response).await["error"]["code"], expected_code);
    }
}

#[tokio::test]
async fn clock_skew_and_nonce_replay_have_stable_rejections() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let stale = signed_node_request(
        &node,
        "GET",
        &path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc() - time::Duration::seconds(301)),
        &nonce(26),
    );
    let response = app.router.clone().oneshot(stale).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["error"]["code"], "clock_skew");

    let timestamp = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let replayed_nonce = nonce(27);
    let first = signed_node_request(&node, "GET", &path, Vec::new(), timestamp, &replayed_nonce);
    assert_eq!(
        app.router.clone().oneshot(first).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let second = signed_node_request(&node, "GET", &path, Vec::new(), timestamp, &replayed_nonce);
    let response = app.router.clone().oneshot(second).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["error"]["code"], "nonce_replayed");
}

#[tokio::test]
async fn desired_empty_fetch_is_authenticated_and_nonce_scope_is_per_node() {
    let app = TestApp::new();
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    let shared_nonce = nonce(28);
    let timestamp = Timestamp::from_datetime(OffsetDateTime::now_utc());

    for node in [&first, &second] {
        let path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
        let request = signed_node_request(node, "GET", &path, Vec::new(), timestamp, &shared_nonce);
        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .len(),
            0
        );
    }
}

#[tokio::test]
async fn controller_epoch_change_fences_previously_signed_requests() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let request = signed_node_request(
        &node,
        "GET",
        &path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(31),
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE networks SET controller_epoch = ?1",
            [ControllerInstanceId::new().to_string()],
        )
        .unwrap();
    drop(connection);

    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json(response).await["error"]["code"], "signature_invalid");
}

#[tokio::test]
async fn expired_nonces_are_pruned_by_the_next_authenticated_request() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let path = format!("/v1/nodes/{}/desired?afterRevision=0", node.node_id);
    let timestamp = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let first_nonce = nonce(32);
    let first = signed_node_request(&node, "GET", &path, Vec::new(), timestamp, &first_nonce);
    assert_eq!(
        app.router.clone().oneshot(first).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let first_hash = sha2::Sha256::digest(first_nonce.as_str().as_bytes());
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE node_request_nonces SET expires_at = 0
             WHERE node_id = ?1 AND nonce_hash = ?2",
            rusqlite::params![node.node_id.to_string(), first_hash.as_slice()],
        )
        .unwrap();
    drop(connection);

    let second = signed_node_request(&node, "GET", &path, Vec::new(), timestamp, &nonce(33));
    assert_eq!(
        app.router.clone().oneshot(second).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let stale_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM node_request_nonces
             WHERE node_id = ?1 AND nonce_hash = ?2",
            rusqlite::params![node.node_id.to_string(), first_hash.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stale_count, 0);
}

#[tokio::test]
async fn desired_publication_is_signed_canonical_monotonic_and_immutable() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let body = desired_state_body();

    let pending = publish_desired(&app, node.node_id, &body).await;
    assert_eq!(pending.status(), StatusCode::CONFLICT);
    assert_eq!(json(pending).await["error"]["code"], "state_conflict");
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let before: (i64, i64) = connection
        .query_row(
            "SELECT last_revision, (SELECT COUNT(*) FROM config_revisions) FROM networks",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, (0, 0));
    drop(connection);

    assert_eq!(
        admin_node_action(&app, node.node_id, "approve")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let first_response = publish_desired(&app, node.node_id, &body).await;
    assert_eq!(first_response.status(), StatusCode::CREATED);
    let first: SignedDesiredState = serde_json::from_value(json(first_response).await).unwrap();
    verify_desired_state_signature(
        &first.document,
        &first.signature,
        &app.controller_public_key,
    )
    .unwrap();
    assert_eq!(first.document.schema_version, 2);
    assert_eq!(first.document.xray.listen_port, 10_443);
    assert_eq!(first.document.xray.public_port, Some(443));
    assert_eq!(first.document.node_id, node.node_id);
    assert_eq!(first.document.revision.get(), 1);
    assert_eq!(
        first.document.xray.server_names,
        vec!["a.example.test".to_string(), "z.example.test".to_string()]
    );
    assert!(first
        .document
        .users
        .windows(2)
        .all(|pair| pair[0].user_id <= pair[1].user_id));

    let second_response = publish_desired(&app, node.node_id, &body).await;
    assert_eq!(second_response.status(), StatusCode::CREATED);
    let second: SignedDesiredState = serde_json::from_value(json(second_response).await).unwrap();
    assert_eq!(second.document.revision.get(), 2);
    assert_eq!(
        second.document.signing_key_id,
        first.document.signing_key_id
    );
    verify_desired_state_signature(
        &second.document,
        &second.signature,
        &app.controller_public_key,
    )
    .unwrap();

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let revisions: Vec<(i64, Option<i64>)> = connection
        .prepare("SELECT revision, parent_revision FROM config_revisions ORDER BY revision")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(revisions, vec![(1, None), (2, Some(1))]);
    let (last_revision, desired_revision): (i64, i64) = connection
        .query_row(
            "SELECT nw.last_revision, n.desired_revision
             FROM networks AS nw JOIN nodes AS n ON n.network_id = nw.network_id
             WHERE n.node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((last_revision, desired_revision), (2, 2));
    assert!(connection
        .execute(
            "UPDATE config_revisions SET created_at = created_at + 1 WHERE revision = 1",
            [],
        )
        .is_err());
    assert!(connection
        .execute("DELETE FROM node_revision_targets WHERE revision = 1", [],)
        .is_err());
    let audit: String = connection
        .query_row(
            "SELECT group_concat(details_json, '') FROM audit_events
             WHERE event_type LIKE 'node.desired-state-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    for user in &first.document.users {
        assert!(!audit.contains(user.vless_uuid.expose_secret()));
    }
}

#[tokio::test]
async fn desired_publication_paths_require_known_canonical_node_ids() {
    let app = TestApp::new();
    let body = desired_state_body();
    for node_id in [
        "not-a-uuid".to_string(),
        "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".to_string(),
        NodeId::new().to_string(),
    ] {
        let response = app
            .router
            .clone()
            .oneshot(
                Request::post(format!("/v1/admin/nodes/{node_id}/desired-state"))
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json(response).await["error"]["code"], "not_found");
    }
}

#[tokio::test]
async fn desired_fetch_returns_verified_latest_state_or_strict_empty_204() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let first = approve_and_publish(&app, &node, &desired_state_body()).await;

    let response = fetch_desired(&app, &node, 0, 70).await;
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: SignedDesiredState = serde_json::from_value(json(response).await).unwrap();
    assert_eq!(fetched, first);

    let response = fetch_desired(&app, &node, 1, 71).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty());

    let second_response = publish_desired(&app, node.node_id, &desired_state_body()).await;
    let second: SignedDesiredState = serde_json::from_value(json(second_response).await).unwrap();
    let response = fetch_desired(&app, &node, 1, 72).await;
    let fetched: SignedDesiredState = serde_json::from_value(json(response).await).unwrap();
    assert_eq!(fetched, second);

    for (query, nonce_byte) in [
        ("afterRevision=01", 73),
        ("afterRevision=1&extra=true", 74),
        ("afterRevision=99999999999999999999", 75),
    ] {
        let path = format!("/v1/nodes/{}/desired?{query}", node.node_id);
        let request = signed_node_request(
            &node,
            "GET",
            &path,
            Vec::new(),
            Timestamp::from_datetime(OffsetDateTime::now_utc()),
            &nonce(nonce_byte),
        );
        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json(response).await["error"]["code"], "validation_failed");
    }

    let wrong_path = format!("/v1/nodes/{}/desired?afterRevision=0", NodeId::new());
    let request = signed_node_request(
        &node,
        "GET",
        &wrong_path,
        Vec::new(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(76),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json(response).await["error"]["code"],
        "authentication_failed"
    );
}

#[tokio::test]
async fn corrupt_desired_artifacts_fail_closed() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    approve_and_publish(&app, &node, &desired_state_body()).await;

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute_batch("DROP TRIGGER config_revisions_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE config_revisions
             SET artifact_json = replace(artifact_json, '0.2.0', '9.9.9')
             WHERE revision = 1",
            [],
        )
        .unwrap();
    drop(connection);

    let response = fetch_desired(&app, &node, 0, 77).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json(response).await["error"]["code"], "internal");
}

#[tokio::test]
async fn revision_results_are_monotonic_idempotent_and_digest_bound() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let desired = approve_and_publish(&app, &node, &desired_state_body()).await;
    let revision = desired.document.revision;
    let received = revision_result(RevisionResultState::Received, 0, None);
    assert_eq!(
        report_result(&app, &node, revision, &received, 80)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        report_result(&app, &node, revision, &received, 81)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let mut conflicting_received = received.clone();
    conflicting_received.completed_at = "2026-07-11T20:00:03Z".parse().unwrap();
    let response = report_result(&app, &node, revision, &conflicting_received, 82).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["error"]["code"],
        "invalid_state_transition"
    );

    let validated = revision_result(RevisionResultState::Validated, 7, None);
    assert_eq!(
        report_result(&app, &node, revision, &validated, 83)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let wrong_digest = revision_result(RevisionResultState::Applied, 8, None);
    let response = report_result(&app, &node, revision, &wrong_digest, 84).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["error"]["code"],
        "invalid_state_transition"
    );
    let applied = revision_result(RevisionResultState::Applied, 7, None);
    assert_eq!(
        report_result(&app, &node, revision, &applied, 85)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let response = report_result(&app, &node, revision, &validated, 86).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["error"]["code"],
        "invalid_state_transition"
    );

    let beyond_target = Revision::new(2).unwrap();
    let response = report_result(&app, &node, beyond_target, &received, 87).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    assert_revision_journal_progress(&app, node.node_id);

    let path = format!("/v1/nodes/{}/revisions/01/result", node.node_id);
    let request = signed_node_request(
        &node,
        "PUT",
        &path,
        serde_json::to_vec(&received).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &nonce(88),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(response).await["error"]["code"], "not_found");
}

#[tokio::test]
async fn rollback_requires_validation_and_an_earlier_target_for_the_same_node() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let other = enroll_signed_node(&app).await;
    approve_node(&app, node.node_id).await;
    approve_node(&app, other.node_id).await;
    let first_response = publish_desired(&app, node.node_id, &desired_state_body()).await;
    let first: SignedDesiredState = serde_json::from_value(json(first_response).await).unwrap();
    let other_response = publish_desired(&app, other.node_id, &desired_state_body()).await;
    let other_revision: SignedDesiredState =
        serde_json::from_value(json(other_response).await).unwrap();
    let third_response = publish_desired(&app, node.node_id, &desired_state_body()).await;
    let third: SignedDesiredState = serde_json::from_value(json(third_response).await).unwrap();
    assert_eq!(
        (
            first.document.revision.get(),
            other_revision.document.revision.get(),
            third.document.revision.get()
        ),
        (1, 2, 3)
    );

    report_applied_revision(&app, &node, first.document.revision, 7, [96, 97, 98]).await;

    let validated = revision_result(RevisionResultState::Validated, 9, None);
    assert_eq!(
        report_result(&app, &node, third.document.revision, &validated, 90)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let wrong_target = revision_result(
        RevisionResultState::RolledBack,
        7,
        Some(other_revision.document.revision),
    );
    let response = report_result(&app, &node, third.document.revision, &wrong_target, 91).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let valid_rollback = revision_result(
        RevisionResultState::RolledBack,
        7,
        Some(first.document.revision),
    );
    assert_eq!(
        report_result(&app, &node, third.document.revision, &valid_rollback, 92,)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_cached_progress(&app, node.node_id, (3, 3, 3, Some(3), Some(1)));

    let mut rolled_back_heartbeat = heartbeat();
    rolled_back_heartbeat.revisions = RevisionProgress {
        desired_revision: Some(third.document.revision),
        received_revision: Some(third.document.revision),
        validated_revision: Some(third.document.revision),
        applied_revision: Some(first.document.revision),
    };
    assert_eq!(
        post_heartbeat(&app, &node, &rolled_back_heartbeat, 99)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let non_target = revision_result(RevisionResultState::Received, 0, None);
    let response = report_result(
        &app,
        &node,
        other_revision.document.revision,
        &non_target,
        93,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(json(response).await["error"]["code"], "not_found");

    let fourth_response = publish_desired(&app, node.node_id, &desired_state_body()).await;
    let fourth: SignedDesiredState = serde_json::from_value(json(fourth_response).await).unwrap();
    let received = revision_result(RevisionResultState::Received, 0, None);
    assert_eq!(
        report_result(&app, &node, fourth.document.revision, &received, 94)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let rollback_without_validation = revision_result(
        RevisionResultState::RolledBack,
        7,
        Some(third.document.revision),
    );
    let response = report_result(
        &app,
        &node,
        fourth.document.revision,
        &rollback_without_validation,
        95,
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn heartbeat_cannot_overwrite_targets_or_invent_journal_progress() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let first = approve_and_publish(&app, &node, &desired_state_body()).await;
    assert_eq!(
        post_heartbeat(&app, &node, &heartbeat(), 100)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let mut forged = heartbeat();
    forged.revisions = RevisionProgress {
        desired_revision: Some(first.document.revision),
        received_revision: Some(first.document.revision),
        validated_revision: None,
        applied_revision: None,
    };
    let response = post_heartbeat(&app, &node, &forged, 101).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["error"]["code"], "state_conflict");

    let mut fetched_only = heartbeat();
    fetched_only.revisions.desired_revision = Some(first.document.revision);
    assert_eq!(
        post_heartbeat(&app, &node, &fetched_only, 102)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let received = revision_result(RevisionResultState::Received, 0, None);
    assert_eq!(
        report_result(&app, &node, first.document.revision, &received, 103)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let second_response = publish_desired(&app, node.node_id, &desired_state_body()).await;
    let second: SignedDesiredState = serde_json::from_value(json(second_response).await).unwrap();
    let mut old_progress = heartbeat();
    old_progress.revisions = RevisionProgress {
        desired_revision: Some(first.document.revision),
        received_revision: Some(first.document.revision),
        validated_revision: None,
        applied_revision: None,
    };
    assert_eq!(
        post_heartbeat(&app, &node, &old_progress, 104)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let mut forged_second = old_progress;
    forged_second.revisions.desired_revision = Some(second.document.revision);
    forged_second.revisions.received_revision = Some(second.document.revision);
    let response = post_heartbeat(&app, &node, &forged_second, 105).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_cached_progress(&app, node.node_id, (2, 1, 1, None, None));
}

#[tokio::test]
async fn desired_state_and_result_journal_survive_restart() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let desired = approve_and_publish(&app, &node, &desired_state_body()).await;
    let received = revision_result(RevisionResultState::Received, 0, None);
    assert_eq!(
        report_result(&app, &node, desired.document.revision, &received, 110)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let expected_public_key = app.controller_public_key.clone();
    let app = app.restart();
    assert_eq!(app.controller_public_key, expected_public_key);
    let response = fetch_desired(&app, &node, 0, 111).await;
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: SignedDesiredState = serde_json::from_value(json(response).await).unwrap();
    assert_eq!(fetched, desired);
    assert_eq!(
        report_result(&app, &node, desired.document.revision, &received, 112)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT user_version FROM pragma_user_version),
                (SELECT COUNT(*) FROM schema_migrations),
                (SELECT COUNT(*) FROM config_revisions),
                (SELECT COUNT(*) FROM node_revision_results),
                (SELECT received_revision FROM nodes WHERE node_id = ?1)",
            [node.node_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(durable, (5, 5, 1, 1, 1));
}
