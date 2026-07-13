use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::account::{
    decode_member_setup_code, AccountNodeAssignmentStatus, AccountNodeProvisioningState,
    AccountStatus, AccountSummary, ConsumeAccountResetTokenRequest,
    ConsumeAccountResetTokenResponse, ConsumeDeviceActivationRequest,
    CreateDeviceActivationRequest, CreateDeviceSessionResponse, CreateSessionRequest,
    DeviceEnrollment, IssueAccountResetTokenRequest, IssueAccountResetTokenResponse,
    MemberSetupActivation, RefreshSessionRequest, RefreshSessionResponse,
    SetAccountPasswordRequest, SignedProfileBundle,
};
use control_protocol::account_crypto::{
    device_activation_proof_transcript, device_login_proof_transcript,
};
use control_protocol::crypto::{
    Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest, X25519PublicKey,
};
use control_protocol::desired::verify_desired_state_signature;
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, EnrollmentInvitation,
};
use control_protocol::error::ErrorCode;
use control_protocol::id::{
    ControllerInstanceId, Count, DeviceId, EndpointId, NodeId, NodeKeyId, Revision, SequenceNumber,
    Timestamp, UserId,
};
use control_protocol::idempotency::IDEMPOTENCY_KEY_HEADER;
use control_protocol::node::{
    decode_node_setup_code, CreateNodeInvitationRequest, CreateNodeInvitationResponse,
    DesiredXrayState, EndpointCandidate, EndpointMode, EndpointReadiness, EndpointSource,
    EnrollNodeRequest, EnrollNodeResponse, NodeCapability, NodeHeartbeat, NodeInitialConfiguration,
    NodeLifecycleState, NodePublicMaterial, NodeRuntimeState, OperatorCohortRollbackRequest,
    OperatorNodeRollbackRequest, OperatorRollbackReason, OperatorRollbackResponse,
    OperatorRollbackTarget, ProviderConsent, RevisionProgress, RevisionResult, RevisionResultState,
    SignedDesiredState, SignedNodeHeartbeatStatus,
};
use control_protocol::node_status::verify_node_heartbeat_status_signature;
use control_protocol::request_auth::NodeRequestSigningInput;
use control_protocol::secret::Secret;
use control_protocol::telemetry::{
    TelemetryBatch, TelemetryBatchAcknowledgement, TelemetryCursor, TelemetryEvent,
    TelemetryEventKind, TELEMETRY_SCHEMA_VERSION,
};
use control_server::db::SCHEMA_VERSION;
use control_server::probe::{
    TcpProbeCompletion, TcpProbeErrorCode, TcpProbeLoopOptions, TcpProbeResult,
};
use control_server::protocol_canary::{ProtocolCanaryLoopOptions, ProtocolCanaryResult};
use control_server::{build_router, AppState, Database, ServiceConfig};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use futures_util::stream;
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use serde_json::Value;
use sha2::Digest as _;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr as _;
use std::time::Duration;
use tempfile::TempDir;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "integration-bootstrap-token-with-enough-entropy";

struct TestApp {
    temp: TempDir,
    router: axum::Router,
    controller_public_key: Ed25519PublicKey,
    database: Database,
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
            database.clone(),
            config.bootstrap_token,
            config.controller_origin,
            config.request_timeout,
        );
        Self {
            temp,
            router: build_router(state),
            controller_public_key,
            database,
        }
    }

    fn restart(self) -> Self {
        let Self {
            temp,
            router,
            controller_public_key: _,
            database,
        } = self;
        drop(router);
        drop(database);
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
                .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&CreateNodeInvitationRequest {
                        display_name: "Friend host".to_string(),
                        expires_in_seconds,
                        initial_configuration: None,
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    decode_node_setup_code(body["setupCode"].as_str().unwrap())
        .unwrap()
        .invitation
}

async fn create_automatic_invitation(app: &TestApp) -> (CreateNodeInvitationResponse, String) {
    let request = CreateNodeInvitationRequest {
        display_name: "Friend host".to_string(),
        expires_in_seconds: 900,
        initial_configuration: Some(NodeInitialConfiguration {
            min_agent_version: "0.1.0".to_string(),
            xray: DesiredXrayState {
                listen_port: 10_443,
                public_port: Some(8_443),
                server_names: vec!["www.microsoft.com".to_string()],
                target: "www.microsoft.com:443".to_string(),
            },
        }),
    };
    let response = app
        .router
        .clone()
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json(response).await;
    let setup_code = body["setupCode"].as_str().unwrap().to_string();
    let invitation = decode_node_setup_code(&setup_code).unwrap().invitation;
    (invitation, setup_code)
}

async fn post_invitation_with_key(
    app: &TestApp,
    request: &CreateNodeInvitationRequest,
    idempotency_key: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post("/v1/admin/node-invitations")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
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
        display_name: "Friend host".to_string(),
        capabilities: vec![
            NodeCapability::Xray,
            NodeCapability::DirectTcp,
            NodeCapability::Pcp,
            NodeCapability::NatPmp,
            NodeCapability::Upnp,
        ],
        identity_public_key,
        public_material: Some(NodePublicMaterial {
            reality_public_key: encryption_public_key.clone(),
            reality_short_id: "0123456789abcdef".to_string(),
        }),
        encryption_public_key,
        nonce,
        proof: Ed25519Signature::from_str(&URL_SAFE_NO_PAD.encode([0_u8; 64])).unwrap(),
        provider_consent: ProviderConsent {
            policy_version: "2026-07-11".to_string(),
            host_owner_consented: true,
            exit_ip_disclosure_accepted: true,
            router_mapping_accepted: true,
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

fn resign_enrollment(
    invitation: &CreateNodeInvitationResponse,
    request: &mut EnrollNodeRequest,
    signing_key: &SigningKey,
) {
    let invitation_context = EnrollmentInvitation {
        invitation_id: invitation.invitation_id,
        purpose: invitation.purpose,
        expires_at: invitation.expires_at,
        controller_origin: &invitation.controller_origin,
        controller_fingerprint: &invitation.controller_fingerprint,
    };
    let transcript = enrollment_request_transcript(&invitation_context, request).unwrap();
    request.proof = Ed25519Signature::from_str(
        &URL_SAFE_NO_PAD.encode(signing_key.sign(&transcript).to_bytes()),
    )
    .unwrap();
}

async fn enroll(app: &TestApp, request: &EnrollNodeRequest) -> axum::response::Response {
    let path = if request.public_material.is_some() {
        "/v2/nodes/enroll"
    } else {
        "/v1/nodes/enroll"
    };
    app.router
        .clone()
        .oneshot(
            Request::post(path)
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

async fn admin_json_request(
    app: &TestApp,
    method: &str,
    uri: &str,
    body: Value,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn admin_json_request_with_key(
    app: &TestApp,
    method: &str,
    uri: &str,
    body: Value,
    idempotency_key: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn admin_accounts(app: &TestApp) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::get("/v1/admin/accounts")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn only_account(app: &TestApp) -> AccountSummary {
    let response = admin_accounts(app).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    serde_json::from_value(body["accounts"][0].clone()).unwrap()
}

fn provisioning_state(account: &AccountSummary, node_id: NodeId) -> AccountNodeProvisioningState {
    account
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == node_id)
        .unwrap()
        .provisioning_state
}

async fn create_account(app: &TestApp, display_name: &str) -> AccountSummary {
    let response = create_account_with_key(app, display_name, &Uuid::new_v4().to_string()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    serde_json::from_value(json(response).await).unwrap()
}

async fn create_account_with_key(
    app: &TestApp,
    display_name: &str,
    idempotency_key: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post("/v1/admin/accounts")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "displayName": display_name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn replace_account_nodes(
    app: &TestApp,
    user_id: UserId,
    node_ids: &[NodeId],
) -> axum::response::Response {
    admin_json_request(
        app,
        "PUT",
        &format!("/v1/admin/accounts/{user_id}/nodes"),
        serde_json::json!({ "nodeIds": node_ids }),
    )
    .await
}

async fn set_account_status(
    app: &TestApp,
    user_id: UserId,
    status: AccountStatus,
) -> axum::response::Response {
    admin_json_request(
        app,
        "PUT",
        &format!("/v1/admin/accounts/{user_id}/status"),
        serde_json::json!({ "status": status }),
    )
    .await
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesiredPublicationSummary {
    node_id: NodeId,
    revision: Revision,
    schema_version: u16,
    user_count: usize,
    created: bool,
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

fn fresh_nonce() -> Nonce {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Nonce::from_str(&URL_SAFE_NO_PAD.encode(bytes)).unwrap()
}

fn heartbeat() -> NodeHeartbeat {
    NodeHeartbeat {
        heartbeat_generation: SequenceNumber::new(1).unwrap(),
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
        endpoints: Vec::new(),
        telemetry_cursor: SequenceNumber::new(9).unwrap(),
    }
}

fn endpoint_candidate(
    revision: Revision,
    mode: EndpointMode,
    source: EndpointSource,
    address: &str,
    port: u16,
) -> EndpointCandidate {
    EndpointCandidate {
        endpoint_id: EndpointId::new(),
        mode,
        source,
        address: address.to_string(),
        port,
        applied_revision: revision,
        observed_at: "2026-07-11T20:00:00Z".parse().unwrap(),
        expires_at: (source != EndpointSource::Manual)
            .then(|| "2026-07-11T21:00:00Z".parse().unwrap()),
    }
}

async fn setup_applied_heartbeat(app: &TestApp) -> (SignedNode, NodeHeartbeat) {
    let node = enroll_signed_node(app).await;
    approve_node(app, node.node_id).await;
    let desired = publish_and_fetch_desired(app, &node, &desired_state_body()).await;
    let revision = desired.document.revision;
    report_applied_revision(app, &node, revision, 7, [20, 21, 22]).await;
    let mut current = heartbeat();
    current.revisions = RevisionProgress {
        desired_revision: Some(revision),
        received_revision: Some(revision),
        validated_revision: Some(revision),
        applied_revision: Some(revision),
    };
    current.endpoints = vec![endpoint_candidate(
        revision,
        EndpointMode::Direct,
        EndpointSource::Manual,
        "node.example.test",
        443,
    )];
    (node, current)
}

fn desired_state_body() -> Value {
    serde_json::json!({
        "minAgentVersion": "0.2.0",
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

async fn publication_summary(
    response: axum::response::Response,
    expected_status: StatusCode,
) -> DesiredPublicationSummary {
    assert_eq!(response.status(), expected_status);
    serde_json::from_value(json(response).await).unwrap()
}

async fn fetch_published_desired(
    app: &TestApp,
    node: &SignedNode,
    publication: &DesiredPublicationSummary,
) -> SignedDesiredState {
    assert_eq!(publication.node_id, node.node_id);
    let after_revision = publication.revision.get() - 1;
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
        &fresh_nonce(),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let desired: SignedDesiredState = serde_json::from_value(json(response).await).unwrap();
    assert_eq!(desired.document.revision, publication.revision);
    assert_eq!(desired.document.schema_version, publication.schema_version);
    assert_eq!(
        desired.document.users.len(),
        publication.user_count.saturating_add(1)
    );
    desired
}

async fn publish_and_fetch_desired(
    app: &TestApp,
    node: &SignedNode,
    body: &Value,
) -> SignedDesiredState {
    let response = publish_desired(app, node.node_id, body).await;
    let publication = publication_summary(response, StatusCode::CREATED).await;
    assert!(publication.created);
    fetch_published_desired(app, node, &publication).await
}

async fn reconcile_desired(app: &TestApp, node_id: NodeId) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::put(format!("/v1/admin/nodes/{node_id}/reconcile"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
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
    publish_and_fetch_desired(app, node, body).await
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

async fn fetch_desired_ok(
    app: &TestApp,
    node: &SignedNode,
    after_revision: Revision,
    nonce_byte: u8,
) -> SignedDesiredState {
    let response = fetch_desired(app, node, after_revision.get(), nonce_byte).await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_value(json(response).await).unwrap()
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

async fn accepted_heartbeat_status(
    response: axum::response::Response,
) -> SignedNodeHeartbeatStatus {
    let status = response.status();
    let body = json(response).await;
    assert_eq!(status, StatusCode::OK, "unexpected heartbeat body: {body}");
    serde_json::from_value(body).unwrap()
}

fn assert_heartbeat_status_authentic(
    app: &TestApp,
    node: &SignedNode,
    heartbeat: &NodeHeartbeat,
    status: &SignedNodeHeartbeatStatus,
) {
    status
        .document
        .validate_for(
            node.node_id,
            heartbeat.heartbeat_generation,
            node.controller_instance_id,
        )
        .unwrap();
    verify_node_heartbeat_status_signature(
        &status.document,
        &status.signature,
        &app.controller_public_key,
    )
    .unwrap();
}

fn assert_heartbeat_status_redacted(status: &SignedNodeHeartbeatStatus) {
    let public_status = serde_json::to_value(status).unwrap();
    let endpoint = &public_status["document"]["endpoints"][0];
    assert!(endpoint.get("address").is_none());
    assert!(endpoint.get("port").is_none());
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

fn assert_empty_member_snapshot_journal_is_immutable_and_redacted(app: &TestApp) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let member_snapshots: (i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM node_revision_member_snapshots),
                (SELECT COUNT(*) FROM node_revision_member_credentials)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(member_snapshots, (2, 0));
    assert!(connection
        .execute(
            "UPDATE node_revision_member_snapshots SET created_at = created_at + 1",
            [],
        )
        .is_err());
    let audit: String = connection
        .query_row(
            "SELECT group_concat(details_json, '') FROM audit_events
             WHERE event_type LIKE 'node.desired-state-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!audit.contains("vlessUuid"));
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

async fn approve_configured_node(app: &TestApp, node: &SignedNode) -> SignedDesiredState {
    approve_and_publish(app, node, &desired_state_body()).await
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
        StatusCode::OK
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let (identity_public_key, encryption_public_key, reality_public_key, reality_short_id): (
        String,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT identity_public_key, encryption_public_key,
                    reality_public_key, reality_short_id
             FROM nodes WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    drop(connection);

    let response = admin_nodes(&app).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = std::str::from_utf8(&bytes).unwrap();
    assert!(!raw.contains(&identity_public_key));
    assert!(!raw.contains(&encryption_public_key));
    assert!(!raw.contains(&reality_public_key));
    assert!(!raw.contains(&reality_short_id));
    assert!(!raw.contains("identityPublicKey"));
    assert!(!raw.contains("encryptionPublicKey"));

    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    let summary = &nodes[0];
    assert_eq!(summary["nodeId"], node.node_id.to_string());
    assert!(Uuid::parse_str(summary["networkId"].as_str().unwrap()).is_ok());
    assert_eq!(summary["displayName"], "Friend host");
    assert_eq!(summary["status"], "pending");
    assert_eq!(summary["platform"], "macos-arm64");
    assert_eq!(summary["agentVersion"], "0.2.0");
    assert_eq!(summary["xrayVersion"], "26.7.11");
    assert_eq!(summary["publicMaterialReady"], true);
    assert_eq!(summary["onboardingState"], "awaitingApproval");
    assert_eq!(
        summary["capabilities"],
        serde_json::json!(["xray", "direct-tcp", "pcp", "nat-pmp", "upnp"])
    );
    assert_eq!(summary["providerConsent"]["policyVersion"], "2026-07-11");
    assert_eq!(summary["providerConsent"]["hostOwnerConsented"], true);
    assert_eq!(summary["providerConsent"]["exitIpDisclosureAccepted"], true);
    assert_eq!(summary["providerConsent"]["routerMappingAccepted"], true);
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
async fn invitation_creation_is_durably_idempotent_without_returning_raw_invitation_fields() {
    let app = TestApp::new();
    let key = Uuid::new_v4().to_string();
    let request = CreateNodeInvitationRequest {
        display_name: "Friend host".to_string(),
        expires_in_seconds: 900,
        initial_configuration: None,
    };
    let first = post_invitation_with_key(&app, &request, &key).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = json(first).await;
    assert!(first_body["setupCode"].is_string());
    let setup_link = url::Url::parse(first_body["setupLink"].as_str().unwrap()).unwrap();
    assert_eq!(setup_link.path(), "/join/node");
    assert_eq!(setup_link.fragment(), first_body["setupCode"].as_str());
    assert_eq!(first_body["displayName"], "Friend host");
    assert!(first_body.get("invitationSecret").is_none());
    assert!(first_body.get("invitationId").is_none());
    assert!(first_body.get("controllerFingerprint").is_none());
    let decoded = decode_node_setup_code(first_body["setupCode"].as_str().unwrap()).unwrap();
    let raw_secret = decoded.invitation.invitation_secret.expose_secret().clone();

    let replay = post_invitation_with_key(&app, &request, &key).await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(json(replay).await, first_body);

    let conflicting = CreateNodeInvitationRequest {
        display_name: "Different host".to_string(),
        ..request
    };
    let conflict = post_invitation_with_key(&app, &conflicting, &key).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(conflict).await["error"]["code"],
        "idempotency_key_conflict"
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM node_invitations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    drop(connection);
    let database = std::fs::read(app.database_path()).unwrap();
    assert!(!database
        .windows(raw_secret.len())
        .any(|window| window == raw_secret.as_bytes()));
}

#[tokio::test]
async fn setup_code_automatically_enrolls_approves_and_publishes_one_initial_state() {
    let app = TestApp::new();
    let (invitation, setup_code) = create_automatic_invitation(&app).await;
    let decoded = decode_node_setup_code(&setup_code).unwrap();
    assert_eq!(decoded.display_name, "Friend host");
    assert_eq!(decoded.invitation, invitation);

    let (request, _, signing_key) = signed_enrollment_with_key(&invitation);
    let response = enroll(&app, &request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let enrolled: EnrollNodeResponse = serde_json::from_value(json(response).await).unwrap();
    let node = SignedNode {
        node_id: enrolled.node_id,
        key_id: enrolled.credential.key_id,
        controller_instance_id: enrolled.controller_instance_id,
        signing_key,
    };

    let nodes = json(admin_nodes(&app).await).await;
    assert_eq!(nodes["nodes"][0]["status"], "active");
    assert_eq!(nodes["nodes"][0]["publicMaterialReady"], true);
    assert_eq!(nodes["nodes"][0]["onboardingState"], "awaitingHeartbeat");
    assert_eq!(nodes["nodes"][0]["revisions"]["desiredRevision"], 1);
    let desired_response = fetch_desired(&app, &node, 0, 231).await;
    assert_eq!(desired_response.status(), StatusCode::OK);
    let desired: SignedDesiredState = serde_json::from_value(json(desired_response).await).unwrap();
    assert_eq!(desired.document.users.len(), 1);
    assert_eq!(desired.document.xray.listen_port, 10_443);
    assert_eq!(desired.document.xray.public_port, Some(8_443));

    let retry = enroll(&app, &request).await;
    assert_eq!(retry.status(), StatusCode::OK);
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM nodes),
                (SELECT COUNT(*) FROM config_revisions),
                (SELECT COUNT(*) FROM node_revision_member_snapshots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 1));
}

#[tokio::test]
async fn automatic_bootstrap_requires_public_material_without_consuming_the_invitation() {
    let app = TestApp::new();
    let (invitation, _) = create_automatic_invitation(&app).await;
    let (valid_request, _, signing_key) = signed_enrollment_with_key(&invitation);
    let mut missing_material = valid_request.clone();
    missing_material.public_material = None;
    resign_enrollment(&invitation, &mut missing_material, &signing_key);

    let rejected = enroll(&app, &missing_material).await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(rejected).await["error"]["code"], "validation_failed");

    let accepted = enroll(&app, &valid_request).await;
    assert_eq!(accepted.status(), StatusCode::CREATED);
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
async fn enrollment_recovery_rejects_changed_provider_consent_and_capabilities() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (request, _, signing_key) = signed_enrollment_with_key(&invitation);
    assert_eq!(enroll(&app, &request).await.status(), StatusCode::CREATED);

    let mut changed = request;
    changed.capabilities = vec![NodeCapability::Xray, NodeCapability::DirectTcp];
    changed.provider_consent.router_mapping_accepted = false;
    resign_enrollment(&invitation, &mut changed, &signing_key);
    let rejected = enroll(&app, &changed).await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(json(rejected).await["error"]["code"], "invitation_consumed");
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
async fn router_mapping_capabilities_require_matching_provider_consent() {
    let app = TestApp::new();
    let invitation = create_invitation(&app, 900).await;
    let (valid, _) = signed_enrollment(&invitation);

    let mut missing_consent = valid.clone();
    missing_consent.provider_consent.router_mapping_accepted = false;
    assert!(missing_consent.validate().is_err());

    let mut missing_capability = valid;
    missing_capability.capabilities.retain(|capability| {
        !matches!(
            capability,
            NodeCapability::Pcp | NodeCapability::NatPmp | NodeCapability::Upnp
        )
    });
    assert!(missing_capability.validate().is_err());
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
                .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
                .body(Body::from(
                    serde_json::to_vec(&CreateNodeInvitationRequest {
                        display_name: "Too long lived".to_string(),
                        expires_in_seconds: 3_601,
                        initial_configuration: None,
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
                .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
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
                .header(IDEMPOTENCY_KEY_HEADER, Uuid::new_v4().to_string())
                .body(Body::from_stream(chunks))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json(oversized).await["error"]["code"], "request_too_large");
}

#[tokio::test]
async fn authenticated_heartbeat_persists_only_pending_endpoint_candidates() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    let response = post_heartbeat(&app, &node, &current, 23).await;
    let status = accepted_heartbeat_status(response).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &status);
    assert_eq!(status.document.lifecycle, NodeLifecycleState::Active);
    assert_eq!(status.document.endpoints.len(), 1);
    assert_eq!(
        status.document.endpoints[0].readiness,
        EndpointReadiness::Pending
    );
    assert_heartbeat_status_redacted(&status);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let stored: (String, String, String, Option<i64>, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT status, agent_version, xray_version, applied_revision,
                    telemetry_cursor, provider_paused, last_heartbeat_generation,
                    length(last_heartbeat_sha256)
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
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        stored,
        (
            "active".into(),
            "0.2.0".into(),
            "26.7.11".into(),
            current.revisions.applied_revision.map(Revision::get),
            9,
            0,
            1,
            32
        )
    );
    let endpoints: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM node_endpoint_candidates
             WHERE node_id = ?1 AND withdrawn_at IS NULL",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(endpoints, 1);
    let verification: String = connection
        .query_row(
            "SELECT status FROM node_endpoint_verifications WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(verification, "pending");
    assert!(connection
        .execute(
            "UPDATE node_endpoint_verifications SET status = 'verified' WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .is_err());
    connection
        .execute(
            "UPDATE node_endpoint_verifications
             SET status = 'verified', probe_attempts = 1,
                 last_probe_at = 20, last_success_at = 20, latency_ms = 8,
                 verification_expires_at = 30, updated_at = 20
             WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .unwrap();
    drop(connection);

    let response = post_heartbeat(&app, &node, &current, 24).await;
    let status = accepted_heartbeat_status(response).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &status);
    assert_eq!(
        status.document.endpoints[0].readiness,
        EndpointReadiness::Pending
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let preserved: String = connection
        .query_row(
            "SELECT status FROM node_endpoint_verifications WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(preserved, "verified");
}

#[tokio::test]
async fn heartbeat_status_refreshes_lifecycle_on_an_exact_retry() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let current = heartbeat();

    let pending = accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 120).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &pending);
    assert_eq!(pending.document.lifecycle, NodeLifecycleState::Pending);

    approve_node(&app, node.node_id).await;
    let active = accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 121).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &active);
    assert_eq!(active.document.lifecycle, NodeLifecycleState::Active);
}

#[tokio::test]
async fn heartbeat_candidate_port_must_match_the_signed_public_port() {
    let app = TestApp::new();
    let (node, mut current) = setup_applied_heartbeat(&app).await;
    current.endpoints[0].port = 8443;

    let response = post_heartbeat(&app, &node, &current, 24).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(json(response).await["error"]["code"], "state_conflict");

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let candidates: i64 = connection
        .query_row("SELECT COUNT(*) FROM node_endpoint_candidates", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(candidates, 0);
}

#[tokio::test]
async fn tcp_preflight_is_durable_and_cannot_mark_an_endpoint_verified() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    let pending = accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 25).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &pending);
    assert_eq!(
        pending.document.endpoints[0].readiness,
        EndpointReadiness::Pending
    );

    let job = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("current direct candidate should be due");
    assert_eq!(job.node_id(), node.node_id);
    assert_eq!(job.endpoint_id(), current.endpoints[0].endpoint_id);
    assert_eq!(job.address(), "node.example.test");
    assert_eq!(job.port(), 443);

    let checking =
        accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 122).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &checking);
    assert_eq!(
        checking.document.endpoints[0].readiness,
        EndpointReadiness::Checking
    );

    let result = TcpProbeResult::connected(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        Duration::from_millis(8),
    );
    assert_eq!(
        app.database
            .complete_tcp_probe(job.clone(), result.clone())
            .await
            .unwrap(),
        TcpProbeCompletion::Recorded
    );
    assert_eq!(
        app.database.complete_tcp_probe(job, result).await.unwrap(),
        TcpProbeCompletion::AlreadyRecorded
    );

    let reachable =
        accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 123).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &reachable);
    assert_eq!(
        reachable.document.endpoints[0].readiness,
        EndpointReadiness::TcpReachable
    );
    assert!(reachable.document.endpoints[0].last_checked_at.is_some());
    assert_eq!(reachable.document.endpoints[0].error_code, None);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let attempt: (String, String, String, i64) = connection
        .query_row(
            "SELECT status, resolved_address, result_code, latency_ms
             FROM endpoint_probe_attempts WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        attempt,
        (
            "succeeded".into(),
            "8.8.8.8".into(),
            "direct_tcp_connected".into(),
            8,
        )
    );
    let verification: (String, i64, Option<i64>) = connection
        .query_row(
            "SELECT status, probe_attempts, last_probe_at
             FROM node_endpoint_verifications WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(verification, ("pending".into(), 0, None));
    assert!(connection
        .execute(
            "UPDATE endpoint_probe_attempts
             SET status = 'failed', result_code = 'manual_override',
                 resolved_address = NULL, latency_ms = NULL
             WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .is_err());
    assert!(connection
        .execute(
            "DELETE FROM endpoint_probe_attempts WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .is_err());
}

#[tokio::test]
async fn protocol_canary_is_the_only_worker_path_that_marks_an_endpoint_verified() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 230).await).await;
    let tcp = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .unwrap();
    app.database
        .complete_tcp_probe(
            tcp,
            TcpProbeResult::connected(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                Duration::from_millis(7),
            ),
        )
        .await
        .unwrap();

    let canary = app
        .database
        .claim_protocol_canary(Uuid::new_v4(), ProtocolCanaryLoopOptions::default())
        .await
        .unwrap()
        .expect("TCP-reachable applied endpoint should be due for protocol verification");
    let debug = format!("{canary:?}");
    assert!(debug.contains("[REDACTED]"));
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let raw_canary: String = connection
        .query_row(
            "SELECT vless_uuid FROM endpoint_canary_credentials WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!debug.contains(&raw_canary));
    drop(connection);

    assert_eq!(
        app.database
            .complete_protocol_canary(
                canary,
                ProtocolCanaryResult::Connected {
                    latency: Duration::from_millis(13),
                },
            )
            .await
            .unwrap(),
        TcpProbeCompletion::Recorded
    );
    let verified =
        accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 231).await).await;
    assert_eq!(
        verified.document.endpoints[0].readiness,
        EndpointReadiness::Verified
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let protocol_attempt: (String, String) = connection
        .query_row(
            "SELECT status, result_code FROM endpoint_probe_attempts
             WHERE node_id = ?1 AND phase = 'protocol'",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        protocol_attempt,
        (
            "succeeded".to_string(),
            "direct_protocol_connected".to_string()
        )
    );
}

#[tokio::test]
async fn registered_relay_candidate_uses_the_same_end_to_end_protocol_gate() {
    let app = TestApp::new();
    let (node, mut current) = setup_applied_heartbeat(&app).await;
    let revision = current.endpoints[0].applied_revision;
    let relay_endpoint_id = EndpointId::new();
    current.endpoints = vec![EndpointCandidate {
        endpoint_id: relay_endpoint_id,
        mode: EndpointMode::Relay,
        source: EndpointSource::Relay,
        address: "relay.example.test".to_string(),
        port: 44_443,
        applied_revision: revision,
        observed_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
        expires_at: Some(Timestamp::from_datetime(
            OffsetDateTime::now_utc() + time::Duration::hours(1),
        )),
    }];
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 240).await).await;

    let tcp = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("registered relay listener should receive external TCP preflight");
    app.database
        .complete_tcp_probe(
            tcp,
            TcpProbeResult::connected(
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                Duration::from_millis(9),
            ),
        )
        .await
        .unwrap();

    let canary = app
        .database
        .claim_protocol_canary(Uuid::new_v4(), ProtocolCanaryLoopOptions::default())
        .await
        .unwrap()
        .expect("TCP-reachable relay must still prove VLESS and REALITY end to end");
    app.database
        .complete_protocol_canary(
            canary,
            ProtocolCanaryResult::Connected {
                latency: Duration::from_millis(17),
            },
        )
        .await
        .unwrap();

    let status = accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 241).await).await;
    assert_eq!(status.document.endpoints.len(), 1);
    assert_eq!(status.document.endpoints[0].endpoint_id, relay_endpoint_id);
    assert_eq!(
        status.document.endpoints[0].readiness,
        EndpointReadiness::Verified
    );
}

#[tokio::test]
async fn current_protocol_verification_outranks_tcp_preflight() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 124).await).await;
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    connection
        .execute(
            "UPDATE node_endpoint_verifications
             SET status = 'verified', probe_attempts = 1,
                 last_probe_at = ?1, last_success_at = ?1, latency_ms = 8,
                 error_code = NULL, verification_expires_at = ?2, updated_at = ?1
             WHERE node_id = ?3",
            rusqlite::params![now, now + 60, node.node_id.to_string()],
        )
        .unwrap();
    drop(connection);

    let verified =
        accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 127).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &verified);
    assert_eq!(
        verified.document.endpoints[0].readiness,
        EndpointReadiness::Verified
    );
}

#[tokio::test]
async fn failed_tcp_preflight_returns_only_a_stable_error_code() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 125).await).await;
    let job = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("current direct candidate should be due");
    assert_eq!(
        app.database
            .complete_tcp_probe(
                job,
                TcpProbeResult::failed(TcpProbeErrorCode::TcpUnreachable),
            )
            .await
            .unwrap(),
        TcpProbeCompletion::Recorded
    );

    let failed = accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 126).await).await;
    assert_heartbeat_status_authentic(&app, &node, &current, &failed);
    let endpoint = &failed.document.endpoints[0];
    assert_eq!(endpoint.readiness, EndpointReadiness::TcpUnreachable);
    assert!(endpoint.last_checked_at.is_some());
    assert_eq!(
        endpoint.error_code.as_deref(),
        Some("direct_tcp_unreachable")
    );
}

#[tokio::test]
async fn a_claim_from_an_older_heartbeat_is_not_reported_as_checking() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 128).await).await;
    let job = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("current direct candidate should be due");

    let mut newer = current.clone();
    newer.heartbeat_generation = SequenceNumber::new(2).unwrap();
    let status = accepted_heartbeat_status(post_heartbeat(&app, &node, &newer, 129).await).await;
    assert_heartbeat_status_authentic(&app, &node, &newer, &status);
    assert_eq!(
        status.document.endpoints[0].readiness,
        EndpointReadiness::Pending
    );
    assert_eq!(
        app.database
            .complete_tcp_probe(
                job,
                TcpProbeResult::connected(
                    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                    Duration::from_millis(9),
                ),
            )
            .await
            .unwrap(),
        TcpProbeCompletion::CandidateChanged
    );
}

#[tokio::test]
async fn tcp_preflight_discards_success_for_a_withdrawn_candidate() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    assert_eq!(
        post_heartbeat(&app, &node, &current, 26).await.status(),
        StatusCode::OK
    );
    let job = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("current direct candidate should be due");

    let mut withdrawn = current;
    withdrawn.heartbeat_generation = SequenceNumber::new(2).unwrap();
    withdrawn.endpoints.clear();
    assert_eq!(
        post_heartbeat(&app, &node, &withdrawn, 27).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        app.database
            .complete_tcp_probe(
                job,
                TcpProbeResult::connected(
                    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                    Duration::from_millis(9),
                ),
            )
            .await
            .unwrap(),
        TcpProbeCompletion::CandidateChanged
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let attempt: (String, String) = connection
        .query_row(
            "SELECT status, result_code FROM endpoint_probe_attempts WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(attempt, ("cancelled".into(), "candidate_changed".into()));
    let verification: String = connection
        .query_row(
            "SELECT status FROM node_endpoint_verifications WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(verification, "withdrawn");
}

#[tokio::test]
async fn heartbeat_withdraws_missing_candidates_and_rejects_identity_reuse() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    assert_eq!(
        post_heartbeat(&app, &node, &current, 23).await.status(),
        StatusCode::OK
    );

    let revision = current.revisions.applied_revision.unwrap();
    let mut next_heartbeat = current.clone();
    next_heartbeat.heartbeat_generation = SequenceNumber::new(2).unwrap();
    let relay_candidate = endpoint_candidate(
        revision,
        EndpointMode::Relay,
        EndpointSource::Relay,
        "relay.example.test",
        8443,
    );
    next_heartbeat.endpoints = vec![relay_candidate];
    assert_eq!(
        post_heartbeat(&app, &node, &next_heartbeat, 29)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        post_heartbeat(&app, &node, &next_heartbeat, 30)
            .await
            .status(),
        StatusCode::OK
    );
    let stale = post_heartbeat(&app, &node, &current, 31).await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(json(stale).await["error"]["code"], "state_stale");

    let mut reused_generation = next_heartbeat.clone();
    reused_generation.agent_version = "0.2.1".to_string();
    let conflict = post_heartbeat(&app, &node, &reused_generation, 32).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(json(conflict).await["error"]["code"], "state_conflict");

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let endpoints: Vec<(String, String, i64)> = connection
        .prepare(
            "SELECT mode, address, port FROM node_endpoint_candidates
             WHERE node_id = ?1 AND withdrawn_at IS NULL ORDER BY address",
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
    let verification_states: Vec<String> = connection
        .prepare(
            "SELECT status FROM node_endpoint_verifications
             WHERE node_id = ?1 ORDER BY status",
        )
        .unwrap()
        .query_map([node.node_id.to_string()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(verification_states, vec!["pending", "withdrawn"]);
    drop(connection);

    let mut conflicting_heartbeat = next_heartbeat;
    conflicting_heartbeat.heartbeat_generation = SequenceNumber::new(3).unwrap();
    conflicting_heartbeat.endpoints[0].address = "changed.example.test".to_string();
    let conflict = post_heartbeat(&app, &node, &conflicting_heartbeat, 33).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(json(conflict).await["error"]["code"], "state_conflict");
}

#[tokio::test]
async fn heartbeat_reactivates_an_identical_withdrawn_candidate_for_a_restarted_node() {
    let app = TestApp::new();
    let (node, current) = setup_applied_heartbeat(&app).await;
    accepted_heartbeat_status(post_heartbeat(&app, &node, &current, 242).await).await;

    let job = app
        .database
        .claim_tcp_probe(Uuid::new_v4(), TcpProbeLoopOptions::default())
        .await
        .unwrap()
        .expect("current direct candidate should be due");
    assert_eq!(
        app.database
            .complete_tcp_probe(
                job,
                TcpProbeResult::failed(TcpProbeErrorCode::TcpUnreachable),
            )
            .await
            .unwrap(),
        TcpProbeCompletion::Recorded
    );

    let mut withdrawn = current.clone();
    withdrawn.heartbeat_generation = SequenceNumber::new(2).unwrap();
    withdrawn.endpoints.clear();
    assert_eq!(
        post_heartbeat(&app, &node, &withdrawn, 243).await.status(),
        StatusCode::OK
    );

    let mut restarted = current.clone();
    restarted.heartbeat_generation = SequenceNumber::new(3).unwrap();
    let status =
        accepted_heartbeat_status(post_heartbeat(&app, &node, &restarted, 244).await).await;
    assert_eq!(status.document.endpoints.len(), 1);
    assert_eq!(
        status.document.endpoints[0].readiness,
        EndpointReadiness::Pending
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let candidate: (i64, Option<i64>) = connection
        .query_row(
            "SELECT last_report_generation, withdrawn_at
             FROM node_endpoint_candidates WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(candidate, (3, None));
    let verification: (String, i64, Option<i64>, Option<String>) = connection
        .query_row(
            "SELECT status, probe_attempts, last_probe_at, error_code
             FROM node_endpoint_verifications WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(verification, ("pending".into(), 0, None, None));
    drop(connection);

    let mut changed = restarted;
    changed.heartbeat_generation = SequenceNumber::new(4).unwrap();
    changed.endpoints[0].address = "changed.example.test".to_string();
    let conflict = post_heartbeat(&app, &node, &changed, 245).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(json(conflict).await["error"]["code"], "state_conflict");
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
        StatusCode::OK
    );

    let mut regressed = heartbeat();
    regressed.heartbeat_generation = SequenceNumber::new(2).unwrap();
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
    let first = publish_and_fetch_desired(&app, &node, &body).await;
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
    assert_eq!(first.document.users.len(), 1);

    let second = publish_and_fetch_desired(&app, &node, &body).await;
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
    drop(connection);
    assert_empty_member_snapshot_journal_is_immutable_and_redacted(&app);
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

    let second = publish_and_fetch_desired(&app, &node, &desired_state_body()).await;
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
async fn desired_configuration_rejects_caller_supplied_member_credentials() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    approve_node(&app, node.node_id).await;
    let mut body = desired_state_body();
    body["users"] = serde_json::json!([{
        "userId": UserId::new(),
        "credentialId": Uuid::new_v4(),
        "vlessUuid": Uuid::new_v4(),
        "enabled": true
    }]);

    let response = publish_desired(&app, node.node_id, &body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(response).await["error"]["code"], "validation_failed");
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let revisions: i64 = connection
        .query_row("SELECT COUNT(*) FROM config_revisions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(revisions, 0);
}

#[tokio::test]
async fn admin_desired_responses_redact_member_artifacts() {
    let app = TestApp::new();
    let account = create_account(&app, "Redacted desired user").await;
    let node = enroll_signed_node(&app).await;
    approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let vless_uuid: String = connection
        .query_row(
            "SELECT vless_uuid FROM user_node_credentials WHERE user_id = ?1",
            [account.account.user_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    for response in [
        reconcile_desired(&app, node.node_id).await,
        publish_desired(&app, node.node_id, &desired_state_body()).await,
    ] {
        assert!(matches!(
            response.status(),
            StatusCode::OK | StatusCode::CREATED
        ));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let raw = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!raw.contains(&vless_uuid));
        assert!(!raw.contains("vlessUuid"));
        assert!(!raw.contains("signature"));
        assert!(!raw.contains("document"));
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["nodeId"], node.node_id.to_string());
        assert_eq!(body["userCount"], 1);
    }
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
    let first = publish_and_fetch_desired(&app, &node, &desired_state_body()).await;
    let other_revision = publish_and_fetch_desired(&app, &other, &desired_state_body()).await;
    let third = publish_and_fetch_desired(&app, &node, &desired_state_body()).await;
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
        StatusCode::OK
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

    let fourth = publish_and_fetch_desired(&app, &node, &desired_state_body()).await;
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
        StatusCode::OK
    );

    let mut forged = heartbeat();
    forged.heartbeat_generation = SequenceNumber::new(2).unwrap();
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
    fetched_only.heartbeat_generation = SequenceNumber::new(3).unwrap();
    fetched_only.revisions.desired_revision = Some(first.document.revision);
    assert_eq!(
        post_heartbeat(&app, &node, &fetched_only, 102)
            .await
            .status(),
        StatusCode::OK
    );
    let received = revision_result(RevisionResultState::Received, 0, None);
    assert_eq!(
        report_result(&app, &node, first.document.revision, &received, 103)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );

    let second = publish_and_fetch_desired(&app, &node, &desired_state_body()).await;
    let mut old_progress = heartbeat();
    old_progress.heartbeat_generation = SequenceNumber::new(4).unwrap();
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
        StatusCode::OK
    );

    let mut forged_second = old_progress;
    forged_second.heartbeat_generation = SequenceNumber::new(5).unwrap();
    forged_second.revisions.desired_revision = Some(second.document.revision);
    forged_second.revisions.received_revision = Some(second.document.revision);
    let response = post_heartbeat(&app, &node, &forged_second, 105).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_cached_progress(&app, node.node_id, (2, 1, 1, None, None));
}

#[tokio::test]
async fn account_creation_requires_and_durably_replays_an_idempotency_key() {
    let app = TestApp::new();
    let missing = admin_json_request(
        &app,
        "POST",
        "/v1/admin/accounts",
        serde_json::json!({ "displayName": "Alice" }),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(missing).await["error"]["code"], "validation_failed");

    let key = Uuid::new_v4().to_string();
    let (first, retry) = tokio::join!(
        create_account_with_key(&app, "Alice", &key),
        create_account_with_key(&app, "Alice", &key),
    );
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(retry.status(), StatusCode::CREATED);
    let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
    let retry_bytes = retry.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_bytes, retry_bytes);

    let conflict = create_account_with_key(&app, "Different request", &key).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(conflict).await["error"]["code"],
        "idempotency_key_conflict"
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM users),
                (SELECT COUNT(*) FROM idempotency_records),
                (SELECT length(idempotency_key_sha256) FROM idempotency_records)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 32));
    let stored_key_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM idempotency_records
             WHERE CAST(idempotency_key_sha256 AS TEXT) = ?1",
            [&key],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_key_count, 0);
    drop(connection);

    let app = app.restart();
    let after_restart = create_account_with_key(&app, "Alice", &key).await;
    assert_eq!(after_restart.status(), StatusCode::CREATED);
    let after_restart_bytes = after_restart
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(first_bytes, after_restart_bytes);
}

#[tokio::test]
async fn account_assignments_are_idempotent_and_redact_credentials() {
    let app = TestApp::new();
    let account = create_account(&app, "Alice").await;
    assert_eq!(account.account.status, AccountStatus::Active);
    assert!(account.assignments.is_empty());

    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    approve_configured_node(&app, &first).await;
    approve_configured_node(&app, &second).await;

    let response = replace_account_nodes(
        &app,
        account.account.user_id,
        &[first.node_id, second.node_id],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw_response = String::from_utf8(bytes.to_vec()).unwrap();
    let assigned: AccountSummary = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(assigned.assignments.len(), 2);
    assert!(assigned
        .assignments
        .iter()
        .all(|assignment| assignment.status == AccountNodeAssignmentStatus::Enabled));
    assert!(assigned.assignments.iter().all(|assignment| {
        assignment.provisioning_state == AccountNodeProvisioningState::Pending
    }));
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT credential_id, node_id, vless_uuid, xray_email, version, status
             FROM user_node_credentials WHERE user_id = ?1 ORDER BY node_id, version",
        )
        .unwrap();
    let credentials: Vec<(String, String, String, String, i64, String)> = statement
        .query_map([account.account.user_id.to_string()], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(credentials.len(), 2);
    assert_ne!(credentials[0].2, credentials[1].2);
    for credential in &credentials {
        assert_eq!(credential.4, 1);
        assert_eq!(credential.5, "pending");
        assert_eq!(
            Uuid::parse_str(&credential.2).unwrap().to_string(),
            credential.2
        );
        assert!(!raw_response.contains(&credential.0));
        assert!(!raw_response.contains(&credential.2));
        assert!(!raw_response.contains(&credential.3));
    }
    assert!(!raw_response.contains("credentialId"));
    assert!(!raw_response.contains("vlessUuid"));
    assert!(!raw_response.contains("xrayEmail"));
    drop(statement);
    drop(connection);

    let idempotent = replace_account_nodes(
        &app,
        account.account.user_id,
        &[second.node_id, first.node_id],
    )
    .await;
    assert_eq!(idempotent.status(), StatusCode::OK);
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM user_node_credentials WHERE user_id = ?1),
                (SELECT COUNT(*) FROM config_revisions),
                (SELECT COUNT(*) FROM node_revision_member_snapshots)",
            [account.account.user_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (2, 4, 4));
}

#[tokio::test]
async fn credential_schema_rejects_contradictory_lifecycle_fields() {
    let app = TestApp::new();
    let account = create_account(&app, "Constraint user").await;
    let node = enroll_signed_node(&app).await;
    approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    for sql in [
        "UPDATE user_node_credentials SET activated_at = created_at",
        "UPDATE user_node_credentials SET status = 'active'",
        "UPDATE user_node_credentials
         SET status = 'retiring', retire_after = created_at + 1",
        "UPDATE user_node_credentials SET status = 'revoked'",
    ] {
        assert!(connection.execute(sql, []).is_err());
    }
    let stored: (String, Option<i64>, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT status, activated_at, retire_after, revoked_at
             FROM user_node_credentials",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored, ("pending".to_string(), None, None, None));
}

#[tokio::test]
async fn multi_node_assignments_publish_distinct_snapshots_and_converge_independently() {
    let app = TestApp::new();
    let account = create_account(&app, "Multi-node user").await;
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    let first_baseline = approve_configured_node(&app, &first).await;
    let second_baseline = approve_configured_node(&app, &second).await;

    let assigned = replace_account_nodes(
        &app,
        account.account.user_id,
        &[first.node_id, second.node_id],
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    let assigned: AccountSummary = serde_json::from_value(json(assigned).await).unwrap();
    assert_eq!(
        provisioning_state(&assigned, first.node_id),
        AccountNodeProvisioningState::Pending
    );
    assert_eq!(
        provisioning_state(&assigned, second.node_id),
        AccountNodeProvisioningState::Pending
    );

    let first_desired = fetch_desired_ok(&app, &first, first_baseline.document.revision, 200).await;
    let second_desired =
        fetch_desired_ok(&app, &second, second_baseline.document.revision, 204).await;
    assert_eq!(first_desired.document.users.len(), 2);
    assert_eq!(second_desired.document.users.len(), 2);
    let first_member = first_desired
        .document
        .users
        .iter()
        .find(|user| user.user_id == account.account.user_id)
        .unwrap();
    let second_member = second_desired
        .document
        .users
        .iter()
        .find(|user| user.user_id == account.account.user_id)
        .unwrap();
    assert_ne!(first_member.credential_id, second_member.credential_id);
    assert_ne!(
        first_member.vless_uuid.expose_secret(),
        second_member.vless_uuid.expose_secret()
    );

    report_applied_revision(
        &app,
        &first,
        first_desired.document.revision,
        51,
        [201, 202, 203],
    )
    .await;
    let partial = only_account(&app).await;
    assert_eq!(
        provisioning_state(&partial, first.node_id),
        AccountNodeProvisioningState::Applied
    );
    assert_eq!(
        provisioning_state(&partial, second.node_id),
        AccountNodeProvisioningState::Pending
    );

    report_applied_revision(
        &app,
        &second,
        second_desired.document.revision,
        52,
        [205, 206, 207],
    )
    .await;
    let converged = only_account(&app).await;
    assert!(converged.assignments.iter().all(|assignment| {
        assignment.provisioning_state == AccountNodeProvisioningState::Applied
    }));

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM node_revision_member_snapshots),
                (SELECT COUNT(*) FROM node_revision_member_credentials),
                (SELECT COUNT(*) FROM user_node_credentials WHERE status = 'active')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (4, 2, 2));
    assert!(connection
        .execute(
            "UPDATE node_revision_member_credentials SET user_id = user_id",
            [],
        )
        .is_err());
    let audit: String = connection
        .query_row(
            "SELECT group_concat(details_json, '') FROM audit_events",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!audit.contains(first_member.vless_uuid.expose_secret()));
    assert!(!audit.contains(second_member.vless_uuid.expose_secret()));
}

#[tokio::test]
async fn account_assignment_removal_and_restore_rotate_credentials() {
    let app = TestApp::new();
    let account = create_account(&app, "Alice").await;
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    approve_configured_node(&app, &first).await;
    approve_configured_node(&app, &second).await;
    let assigned = replace_account_nodes(
        &app,
        account.account.user_id,
        &[first.node_id, second.node_id],
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    let assigned: AccountSummary = serde_json::from_value(json(assigned).await).unwrap();
    let second_assignment_id = assigned
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == second.node_id)
        .unwrap()
        .assignment_id;

    let removed = replace_account_nodes(&app, account.account.user_id, &[first.node_id]).await;
    assert_eq!(removed.status(), StatusCode::OK);
    let removed: AccountSummary = serde_json::from_value(json(removed).await).unwrap();
    let removed_second = removed
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == second.node_id)
        .unwrap();
    assert_eq!(removed_second.assignment_id, second_assignment_id);
    assert_eq!(removed_second.status, AccountNodeAssignmentStatus::Disabled);
    assert_eq!(
        removed_second.provisioning_state,
        AccountNodeProvisioningState::NotProvisioned
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let removed_status: String = connection
        .query_row(
            "SELECT status FROM user_node_credentials
             WHERE user_id = ?1 AND node_id = ?2 ORDER BY version DESC LIMIT 1",
            [
                account.account.user_id.to_string(),
                second.node_id.to_string(),
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(removed_status, "revoked");
    drop(connection);

    let restored = replace_account_nodes(
        &app,
        account.account.user_id,
        &[first.node_id, second.node_id],
    )
    .await;
    assert_eq!(restored.status(), StatusCode::OK);
    let restored: AccountSummary = serde_json::from_value(json(restored).await).unwrap();
    let restored_second = restored
        .assignments
        .iter()
        .find(|assignment| assignment.node_id == second.node_id)
        .unwrap();
    assert_eq!(restored_second.assignment_id, second_assignment_id);
    assert_eq!(restored_second.status, AccountNodeAssignmentStatus::Enabled);
    assert_eq!(
        restored_second.provisioning_state,
        AccountNodeProvisioningState::Pending
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT version, status FROM user_node_credentials
             WHERE user_id = ?1 AND node_id = ?2 ORDER BY version",
        )
        .unwrap();
    let versions: Vec<(i64, String)> = statement
        .query_map(
            [
                account.account.user_id.to_string(),
                second.node_id.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        versions,
        vec![(1, "revoked".to_string()), (2, "pending".to_string())]
    );
}

#[tokio::test]
async fn account_assignment_rejects_unavailable_nodes_atomically() {
    let app = TestApp::new();
    let account = create_account(&app, "Bob").await;
    let active = enroll_signed_node(&app).await;
    let pending = enroll_signed_node(&app).await;
    approve_configured_node(&app, &active).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[active.node_id])
            .await
            .status(),
        StatusCode::OK
    );

    let unavailable = replace_account_nodes(
        &app,
        account.account.user_id,
        &[active.node_id, pending.node_id],
    )
    .await;
    assert_eq!(unavailable.status(), StatusCode::CONFLICT);
    assert_eq!(json(unavailable).await["error"]["code"], "conflict");

    let unconfigured = enroll_signed_node(&app).await;
    approve_node(&app, unconfigured.node_id).await;
    let missing_configuration = replace_account_nodes(
        &app,
        account.account.user_id,
        &[active.node_id, unconfigured.node_id],
    )
    .await;
    assert_eq!(missing_configuration.status(), StatusCode::CONFLICT);

    let unknown_node = replace_account_nodes(
        &app,
        account.account.user_id,
        &[active.node_id, NodeId::new()],
    )
    .await;
    assert_eq!(unknown_node.status(), StatusCode::NOT_FOUND);

    let duplicate = replace_account_nodes(
        &app,
        account.account.user_id,
        &[active.node_id, active.node_id],
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json(duplicate).await["error"]["code"], "validation_failed");

    let unknown_account = replace_account_nodes(&app, UserId::new(), &[active.node_id]).await;
    assert_eq!(unknown_account.status(), StatusCode::NOT_FOUND);
    let malformed_account = admin_json_request(
        &app,
        "PUT",
        "/v1/admin/accounts/not-a-user-id/nodes",
        serde_json::json!({ "nodeIds": [active.node_id] }),
    )
    .await;
    assert_eq!(malformed_account.status(), StatusCode::NOT_FOUND);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM user_node_assignments WHERE user_id = ?1),
                (SELECT COUNT(*) FROM user_node_assignments
                 WHERE user_id = ?1 AND status = 'enabled'),
                (SELECT COUNT(*) FROM user_node_credentials WHERE user_id = ?1),
                (SELECT last_revision FROM networks)",
            [account.account.user_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1, 1, 2));
}

#[tokio::test]
async fn multi_node_assignment_rolls_back_if_a_later_node_has_no_configuration() {
    let app = TestApp::new();
    let account = create_account(&app, "Atomic user").await;
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    approve_node(&app, first.node_id).await;
    approve_node(&app, second.node_id).await;
    let (configured, unconfigured) = if first.node_id < second.node_id {
        (&first, &second)
    } else {
        (&second, &first)
    };
    let baseline = publish_desired(&app, configured.node_id, &desired_state_body()).await;
    assert_eq!(baseline.status(), StatusCode::CREATED);

    let response = replace_account_nodes(
        &app,
        account.account.user_id,
        &[configured.node_id, unconfigured.node_id],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64, i64, i64, Option<i64>) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM user_node_assignments),
                (SELECT COUNT(*) FROM user_node_credentials),
                (SELECT COUNT(*) FROM config_revisions),
                (SELECT COUNT(*) FROM node_revision_member_snapshots),
                (SELECT last_revision FROM networks),
                (SELECT desired_revision FROM nodes WHERE node_id = ?1)",
            [unconfigured.node_id.to_string()],
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
    assert_eq!(durable, (0, 0, 1, 1, 1, None));
}

#[tokio::test]
async fn account_disable_and_reactivation_rotate_credentials() {
    let app = TestApp::new();
    let account = create_account(&app, "Carol").await;
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    approve_configured_node(&app, &first).await;
    approve_configured_node(&app, &second).await;
    assert_eq!(
        replace_account_nodes(
            &app,
            account.account.user_id,
            &[first.node_id, second.node_id],
        )
        .await
        .status(),
        StatusCode::OK
    );

    let disabled = set_account_status(&app, account.account.user_id, AccountStatus::Disabled).await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled: AccountSummary = serde_json::from_value(json(disabled).await).unwrap();
    assert_eq!(disabled.account.status, AccountStatus::Disabled);
    assert!(disabled
        .assignments
        .iter()
        .all(|assignment| assignment.status == AccountNodeAssignmentStatus::Enabled));
    assert!(disabled.assignments.iter().all(|assignment| {
        assignment.provisioning_state == AccountNodeProvisioningState::NotProvisioned
    }));
    let blocked_replace =
        replace_account_nodes(&app, account.account.user_id, &[first.node_id]).await;
    assert_eq!(blocked_replace.status(), StatusCode::CONFLICT);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let revoked: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM user_node_credentials
             WHERE user_id = ?1 AND status = 'revoked'",
            [account.account.user_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revoked, 2);
    drop(connection);

    let active = set_account_status(&app, account.account.user_id, AccountStatus::Active).await;
    assert_eq!(active.status(), StatusCode::OK);
    let active: AccountSummary = serde_json::from_value(json(active).await).unwrap();
    assert_eq!(active.account.status, AccountStatus::Active);
    assert_eq!(
        set_account_status(&app, account.account.user_id, AccountStatus::Active)
            .await
            .status(),
        StatusCode::OK
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let states: (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END)
             FROM user_node_credentials WHERE user_id = ?1",
            [account.account.user_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(states, (4, 2, 2));
}

#[tokio::test]
async fn account_deletion_is_terminal_redacted_and_durable() {
    let app = TestApp::new();
    let account = create_account(&app, "Deleted user").await;
    let node = enroll_signed_node(&app).await;
    approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let deleted = set_account_status(&app, account.account.user_id, AccountStatus::Deleted).await;
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted: AccountSummary = serde_json::from_value(json(deleted).await).unwrap();
    assert_eq!(deleted.account.status, AccountStatus::Deleted);
    assert!(deleted
        .assignments
        .iter()
        .all(|assignment| assignment.status == AccountNodeAssignmentStatus::Deleted));
    assert_eq!(
        set_account_status(&app, account.account.user_id, AccountStatus::Deleted)
            .await
            .status(),
        StatusCode::OK
    );
    let restore = set_account_status(&app, account.account.user_id, AccountStatus::Active).await;
    assert_eq!(restore.status(), StatusCode::CONFLICT);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let non_revoked: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM user_node_credentials
             WHERE user_id = ?1 AND status != 'revoked'",
            [account.account.user_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(non_revoked, 0);
    drop(connection);

    let app = app.restart();
    let listed = admin_accounts(&app).await;
    assert_eq!(listed.status(), StatusCode::OK);
    let bytes = listed.into_body().collect().await.unwrap().to_bytes();
    let raw = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!raw.contains("credentialId"));
    assert!(!raw.contains("vlessUuid"));
    assert!(!raw.contains("xrayEmail"));
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(body["accounts"][0]["account"]["status"], "deleted");
}

#[tokio::test]
async fn applied_account_disable_exposes_removal_pending_and_rotates_on_restore() {
    let app = TestApp::new();
    let account = create_account(&app, "Applied user").await;
    let node = enroll_signed_node(&app).await;
    let baseline = approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let desired_response = fetch_desired(&app, &node, baseline.document.revision.get(), 180).await;
    assert_eq!(desired_response.status(), StatusCode::OK);
    let desired: SignedDesiredState = serde_json::from_value(json(desired_response).await).unwrap();
    assert_eq!(desired.document.users.len(), 2);
    report_applied_revision(&app, &node, desired.document.revision, 44, [181, 182, 183]).await;

    let listed = json(admin_accounts(&app).await).await;
    assert_eq!(
        listed["accounts"][0]["assignments"][0]["provisioningState"],
        "applied"
    );
    let disabled = set_account_status(&app, account.account.user_id, AccountStatus::Disabled).await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled: AccountSummary = serde_json::from_value(json(disabled).await).unwrap();
    assert_eq!(
        disabled.assignments[0].provisioning_state,
        AccountNodeProvisioningState::RemovalPending
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let retiring: (String, bool, bool) = connection
        .query_row(
            "SELECT status, activated_at IS NOT NULL, retire_after IS NOT NULL
             FROM user_node_credentials WHERE user_id = ?1 AND node_id = ?2",
            [
                account.account.user_id.to_string(),
                node.node_id.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retiring, ("retiring".to_string(), true, true));
    drop(connection);

    let restored = set_account_status(&app, account.account.user_id, AccountStatus::Active).await;
    assert_eq!(restored.status(), StatusCode::OK);
    let restored: AccountSummary = serde_json::from_value(json(restored).await).unwrap();
    assert_eq!(
        restored.assignments[0].provisioning_state,
        AccountNodeProvisioningState::Pending
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let states: (i64, i64) = connection
        .query_row(
            "SELECT
                SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END)
             FROM user_node_credentials WHERE user_id = ?1 AND node_id = ?2",
            [
                account.account.user_id.to_string(),
                node.node_id.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(states, (1, 1));
}

#[tokio::test]
async fn rejected_removal_stays_pending_until_a_later_revision_applies() {
    let app = TestApp::new();
    let account = create_account(&app, "Removal user").await;
    let node = enroll_signed_node(&app).await;
    let baseline = approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let assigned = fetch_desired_ok(&app, &node, baseline.document.revision, 210).await;
    report_applied_revision(&app, &node, assigned.document.revision, 61, [211, 212, 213]).await;

    let disabled = set_account_status(&app, account.account.user_id, AccountStatus::Disabled).await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled: AccountSummary = serde_json::from_value(json(disabled).await).unwrap();
    assert_eq!(
        disabled.assignments[0].provisioning_state,
        AccountNodeProvisioningState::RemovalPending
    );
    let removal = fetch_desired_ok(&app, &node, assigned.document.revision, 214).await;
    assert_eq!(removal.document.users.len(), 1);
    assert_eq!(
        report_result(
            &app,
            &node,
            removal.document.revision,
            &revision_result(RevisionResultState::Received, 0, None),
            215,
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        report_result(
            &app,
            &node,
            removal.document.revision,
            &revision_result(RevisionResultState::Rejected, 0, None),
            216,
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        only_account(&app).await.assignments[0].provisioning_state,
        AccountNodeProvisioningState::RemovalPending
    );

    let retry_response = reconcile_desired(&app, node.node_id).await;
    let retry = publication_summary(retry_response, StatusCode::CREATED).await;
    assert!(retry.created);
    assert_eq!(retry.user_count, 0);
    let idempotent_retry = reconcile_desired(&app, node.node_id).await;
    let idempotent_retry = publication_summary(idempotent_retry, StatusCode::OK).await;
    assert!(!idempotent_retry.created);
    assert_eq!(idempotent_retry.revision, retry.revision);
    let fetched_retry = fetch_desired_ok(&app, &node, removal.document.revision, 217).await;
    assert_eq!(fetched_retry.document.revision, retry.revision);
    report_applied_revision(&app, &node, retry.revision, 62, [218, 219, 220]).await;
    assert_eq!(
        only_account(&app).await.assignments[0].provisioning_state,
        AccountNodeProvisioningState::Removed
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let status: String = connection
        .query_row(
            "SELECT status FROM user_node_credentials WHERE user_id = ?1",
            [account.account.user_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "revoked");
}

#[tokio::test]
async fn rolled_back_removal_keeps_access_pending_and_can_be_republished() {
    let app = TestApp::new();
    let account = create_account(&app, "Rollback user").await;
    let node = enroll_signed_node(&app).await;
    let baseline = approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let assigned = fetch_desired_ok(&app, &node, baseline.document.revision, 230).await;
    report_applied_revision(&app, &node, assigned.document.revision, 70, [231, 232, 233]).await;
    assert_eq!(
        set_account_status(&app, account.account.user_id, AccountStatus::Disabled)
            .await
            .status(),
        StatusCode::OK
    );
    let removal = fetch_desired_ok(&app, &node, assigned.document.revision, 234).await;
    for (result, nonce_byte) in [
        (revision_result(RevisionResultState::Received, 0, None), 235),
        (
            revision_result(RevisionResultState::Validated, 71, None),
            236,
        ),
        (
            revision_result(
                RevisionResultState::RolledBack,
                70,
                Some(assigned.document.revision),
            ),
            237,
        ),
    ] {
        assert_eq!(
            report_result(&app, &node, removal.document.revision, &result, nonce_byte,)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        only_account(&app).await.assignments[0].provisioning_state,
        AccountNodeProvisioningState::RemovalPending
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (String, i64) = connection
        .query_row(
            "SELECT credential.status, node.applied_revision
             FROM user_node_credentials AS credential
             JOIN nodes AS node ON node.node_id = credential.node_id
             WHERE credential.user_id = ?1",
            [account.account.user_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        durable,
        ("retiring".to_string(), assigned.document.revision.get())
    );
    drop(connection);
    let retry = reconcile_desired(&app, node.node_id).await;
    assert_eq!(retry.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn disabling_or_revoking_a_node_closes_member_access() {
    let app = TestApp::new();
    let account = create_account(&app, "Dave").await;
    let node = enroll_signed_node(&app).await;
    let baseline = approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let assigned = fetch_desired_ok(&app, &node, baseline.document.revision, 240).await;
    report_applied_revision(&app, &node, assigned.document.revision, 80, [241, 242, 243]).await;

    assert_eq!(
        admin_node_action(&app, node.node_id, "disable")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let listed = json(admin_accounts(&app).await).await;
    assert_eq!(
        listed["accounts"][0]["assignments"][0]["status"],
        "disabled"
    );
    assert_eq!(
        listed["accounts"][0]["assignments"][0]["provisioningState"],
        "removalPending"
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let credential_status: String = connection
        .query_row(
            "SELECT status FROM user_node_credentials WHERE user_id = ?1 AND node_id = ?2",
            [
                account.account.user_id.to_string(),
                node.node_id.to_string(),
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(credential_status, "revoked");
    drop(connection);

    assert_eq!(
        admin_node_action(&app, node.node_id, "revoke")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let listed = json(admin_accounts(&app).await).await;
    assert_eq!(listed["accounts"][0]["assignments"][0]["status"], "deleted");
    assert_eq!(
        listed["accounts"][0]["assignments"][0]["provisioningState"],
        "removalPending"
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT event_type, details_json FROM audit_events
             WHERE target_type = 'node' AND target_id = ?1
               AND event_type IN ('node.disabled', 'node.revoked')
             ORDER BY event_id",
        )
        .unwrap();
    let events: Vec<(String, Value)> = statement
        .query_map([node.node_id.to_string()], |row| {
            let details: String = row.get(1)?;
            Ok((row.get(0)?, serde_json::from_str(&details).unwrap()))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, "node.disabled");
    assert_eq!(events[0].1["memberAssignmentsClosed"], 1);
    assert_eq!(events[0].1["memberCredentialsRevoked"], 1);
    assert_eq!(events[1].0, "node.revoked");
    assert_eq!(events[1].1["memberAssignmentsClosed"], 1);
    assert_eq!(events[1].1["memberCredentialsRevoked"], 0);
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
    assert_eq!(durable, (SCHEMA_VERSION, SCHEMA_VERSION, 1, 1, 1));
}

fn unsigned_device(signing_key: &SigningKey, marker: u8) -> DeviceEnrollment {
    DeviceEnrollment {
        display_name: format!("Connect device {marker}"),
        client_version: "0.1.0".to_string(),
        platform: "macos-arm64".to_string(),
        identity_public_key: URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().to_bytes())
            .parse()
            .unwrap(),
        encryption_public_key: URL_SAFE_NO_PAD.encode([marker; 32]).parse().unwrap(),
        nonce: URL_SAFE_NO_PAD.encode([marker; 32]).parse().unwrap(),
        proof: URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap(),
    }
}

fn signed_login_request(user_id: UserId, password: &str, marker: u8) -> CreateSessionRequest {
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut device = unsigned_device(&signing_key, marker);
    let account = user_id.to_string();
    let transcript =
        device_login_proof_transcript(&account, "https://control.test", &device).unwrap();
    device.proof = URL_SAFE_NO_PAD
        .encode(signing_key.sign(&transcript).to_bytes())
        .parse()
        .unwrap();
    CreateSessionRequest {
        account,
        password: Secret::new(password.to_string()),
        device,
    }
}

async fn set_password(app: &TestApp, user_id: UserId, password: &str) {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::put(format!("/v1/admin/accounts/{user_id}/password"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&SetAccountPasswordRequest {
                        new_password: Secret::new(password.to_string()),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

async fn create_device_activation_for(
    app: &TestApp,
    user_id: UserId,
    key: &str,
) -> (MemberSetupActivation, Vec<u8>) {
    let request = CreateDeviceActivationRequest::default();
    let response = app
        .router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/accounts/{user_id}/device-activations"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, key)
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let activation = decode_member_setup_code(body["setupCode"].as_str().unwrap()).unwrap();
    (activation, bytes)
}

fn signed_activation_request(
    activation: &MemberSetupActivation,
    signing_key: &SigningKey,
    marker: u8,
) -> ConsumeDeviceActivationRequest {
    let mut device = unsigned_device(signing_key, marker);
    let transcript = device_activation_proof_transcript(
        activation.activation_id,
        activation.expires_at,
        "https://control.test",
        &device,
    )
    .unwrap();
    device.proof = URL_SAFE_NO_PAD
        .encode(signing_key.sign(&transcript).to_bytes())
        .parse()
        .unwrap();
    ConsumeDeviceActivationRequest {
        activation_secret: activation.activation_secret.clone(),
        device,
    }
}

async fn post_public_json<T: serde::Serialize>(
    app: &TestApp,
    path: &str,
    request: &T,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn post_public_json_with_key<T: serde::Serialize>(
    app: &TestApp,
    path: &str,
    request: &T,
    idempotency_key: &str,
) -> axum::response::Response {
    app.router
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
                .body(Body::from(serde_json::to_vec(request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn consume_activation_ok(
    app: &TestApp,
    request: &ConsumeDeviceActivationRequest,
) -> (CreateDeviceSessionResponse, Vec<u8>) {
    let response = post_public_json(app, "/v1/device-activations/consume", request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (serde_json::from_slice(&bytes).unwrap(), bytes)
}

async fn issue_reset_token(
    app: &TestApp,
    user_id: UserId,
    idempotency_key: &str,
) -> (IssueAccountResetTokenResponse, Bytes) {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/accounts/{user_id}/reset-tokens"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(IDEMPOTENCY_KEY_HEADER, idempotency_key)
                .body(Body::from(
                    serde_json::to_vec(&IssueAccountResetTokenRequest::default()).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (serde_json::from_slice(&bytes).unwrap(), bytes)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn account_reset_token_is_hashed_single_use_and_concurrently_idempotent() {
    let app = TestApp::new();
    let account = create_account(&app, "Recovery member").await;
    let user_id = account.account.user_id;
    let old_password = "old recovery password";
    let new_password = "new recovery password";
    set_password(&app, user_id, old_password).await;
    let node = enroll_signed_node(&app).await;
    let baseline = approve_configured_node(&app, &node).await;
    assert_eq!(
        replace_account_nodes(&app, user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let assigned = fetch_desired_ok(&app, &node, baseline.document.revision, 130).await;
    report_applied_revision(&app, &node, assigned.document.revision, 80, [131, 132, 133]).await;

    let first_login = signed_login_request(user_id, old_password, 40);
    let first_session: CreateDeviceSessionResponse = serde_json::from_value(
        json(
            post_public_json_with_key(
                &app,
                "/v1/sessions",
                &first_login,
                &Uuid::new_v4().to_string(),
            )
            .await,
        )
        .await,
    )
    .unwrap();
    let second_login = signed_login_request(user_id, old_password, 41);
    let second_session: CreateDeviceSessionResponse = serde_json::from_value(
        json(
            post_public_json_with_key(
                &app,
                "/v1/sessions",
                &second_login,
                &Uuid::new_v4().to_string(),
            )
            .await,
        )
        .await,
    )
    .unwrap();

    let issue_key = Uuid::new_v4().to_string();
    let (issued, first_issue) = issue_reset_token(&app, user_id, &issue_key).await;
    let (replayed_issue, second_issue) = issue_reset_token(&app, user_id, &issue_key).await;
    assert_eq!(first_issue, second_issue);
    assert_eq!(issued, replayed_issue);
    assert!(issued.reset_token.expose_secret().starts_with("rcr1."));
    let database_bytes = std::fs::read(app.database_path()).unwrap();
    assert!(!database_bytes
        .windows(issued.reset_token.expose_secret().len())
        .any(|window| window == issued.reset_token.expose_secret().as_bytes()));

    let consume = ConsumeAccountResetTokenRequest {
        reset_token: issued.reset_token.clone(),
        new_password: Secret::new(new_password.to_string()),
    };
    let consume_key = Uuid::new_v4().to_string();
    let body = serde_json::to_vec(&consume).unwrap();
    let request = || {
        Request::post("/v1/account-reset-tokens/consume")
            .header(header::CONTENT_TYPE, "application/json")
            .header(IDEMPOTENCY_KEY_HEADER, &consume_key)
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let (first, second) = tokio::join!(
        app.router.clone().oneshot(request()),
        app.router.clone().oneshot(request()),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
    let second_bytes = second.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_bytes, second_bytes);
    let reset: ConsumeAccountResetTokenResponse = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(reset.user_id, user_id);
    assert_eq!(reset.revoked_sessions, 2);
    assert_eq!(reset.published_revisions.len(), 1);
    assert!(reset.published_revisions[0] > assigned.document.revision);

    let replay = post_public_json_with_key(
        &app,
        "/v1/account-reset-tokens/consume",
        &consume,
        &consume_key,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        first_bytes
    );
    let consumed = post_public_json_with_key(
        &app,
        "/v1/account-reset-tokens/consume",
        &consume,
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(consumed.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(consumed).await["error"]["code"],
        "account_reset_consumed"
    );

    for session in [first_session, second_session] {
        let refresh = post_public_json_with_key(
            &app,
            "/v1/sessions/refresh",
            &RefreshSessionRequest {
                refresh_credential: session.credentials.refresh_credential,
            },
            &Uuid::new_v4().to_string(),
        )
        .await;
        assert_eq!(refresh.status(), StatusCode::UNAUTHORIZED);
    }
    let new_login = signed_login_request(user_id, new_password, 42);
    assert_eq!(
        post_public_json_with_key(
            &app,
            "/v1/sessions",
            &new_login,
            &Uuid::new_v4().to_string(),
        )
        .await
        .status(),
        StatusCode::CREATED
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT length(secret_verifier) FROM account_reset_tokens),
                (SELECT COUNT(*) FROM account_reset_tokens WHERE consumed_at IS NOT NULL),
                (SELECT COUNT(*) FROM audit_events WHERE event_type = 'account.reset-token-issued'),
                (SELECT COUNT(*) FROM audit_events WHERE event_type = 'account.reset-token-consumed')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(durable, (32, 1, 1, 1));
}

#[tokio::test]
async fn account_reset_token_expiry_is_rejected_and_audited() {
    let app = TestApp::new();
    let account = create_account(&app, "Expired recovery member").await;
    let (issued, _) =
        issue_reset_token(&app, account.account.user_id, &Uuid::new_v4().to_string()).await;
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE account_reset_tokens SET created_at = 0, expires_at = 1",
            [],
        )
        .unwrap();
    drop(connection);
    let response = post_public_json_with_key(
        &app,
        "/v1/account-reset-tokens/consume",
        &ConsumeAccountResetTokenRequest {
            reset_token: issued.reset_token,
            new_password: Secret::new("replacement password".to_string()),
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(
        json(response).await["error"]["code"],
        "account_reset_expired"
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM account_reset_tokens WHERE consumed_at IS NULL),
                (SELECT COUNT(*) FROM audit_events
                 WHERE event_type = 'account.reset-token-rejected'
                   AND json_extract(details_json, '$.reason') = 'expired')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(durable, (1, 1));
}

#[tokio::test]
async fn unknown_account_reset_tokens_do_not_create_persistent_audit_amplification() {
    let app = TestApp::new();
    let before = rusqlite::Connection::open(app.database_path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();

    for index in 0..3 {
        let response = post_public_json_with_key(
            &app,
            "/v1/account-reset-tokens/consume",
            &ConsumeAccountResetTokenRequest {
                reset_token: Secret::new(format!("unknown-reset-token-{index}")),
                new_password: Secret::new("replacement password".to_string()),
            },
            &Uuid::new_v4().to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json(response).await["error"]["code"],
            "account_reset_invalid"
        );
    }

    let after = rusqlite::Connection::open(app.database_path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn admin_device_revoke_is_independent_across_multiple_devices() {
    let app = TestApp::new();
    let account = create_account(&app, "Multi-device member").await;
    let password = "multi device password";
    set_password(&app, account.account.user_id, password).await;
    let mut sessions = Vec::new();
    for marker in [43, 44] {
        let login = signed_login_request(account.account.user_id, password, marker);
        let response =
            post_public_json_with_key(&app, "/v1/sessions", &login, &Uuid::new_v4().to_string())
                .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        sessions.push(
            serde_json::from_value::<CreateDeviceSessionResponse>(json(response).await).unwrap(),
        );
    }
    assert_eq!(
        app.router
            .clone()
            .oneshot(
                Request::post(format!(
                    "/v1/admin/devices/{}/revoke",
                    sessions[0].device_id
                ))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    let revoked = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: sessions[0].credentials.refresh_credential.clone(),
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    let surviving = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: sessions[1].credentials.refresh_credential.clone(),
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(surviving.status(), StatusCode::OK);
}

#[tokio::test]
async fn device_activation_exactly_replays_without_storing_raw_secrets() {
    let app = TestApp::new();
    let account = create_account(&app, "Activation member").await;
    let key = Uuid::new_v4().to_string();
    let (activation, first_creation) =
        create_device_activation_for(&app, account.account.user_id, &key).await;
    let app = app.restart();
    let (replayed, second_creation) =
        create_device_activation_for(&app, account.account.user_id, &key).await;
    assert_eq!(first_creation, second_creation);
    assert_eq!(activation, replayed);

    let delivery: Value = serde_json::from_slice(&first_creation).unwrap();
    let fields = delivery.as_object().unwrap();
    assert_eq!(fields.len(), 4);
    assert_eq!(delivery["displayName"], "Activation member");
    assert_eq!(delivery["expiresAt"], activation.expires_at.to_string());
    assert!(delivery["setupCode"]
        .as_str()
        .unwrap()
        .starts_with("pn-member-v1."));
    let setup_link = url::Url::parse(delivery["setupLink"].as_str().unwrap()).unwrap();
    assert_eq!(
        setup_link.origin().ascii_serialization(),
        "https://control.test"
    );
    assert_eq!(setup_link.path(), "/join/connect");
    assert_eq!(setup_link.fragment(), delivery["setupCode"].as_str());
    for raw_field in [
        "activationId",
        "userId",
        "networkId",
        "activationSecret",
        "controllerOrigin",
        "controllerInstanceId",
        "bundleSigningPublicKey",
    ] {
        assert!(fields.get(raw_field).is_none());
    }
    let raw_delivery = String::from_utf8(first_creation.clone()).unwrap();
    assert!(!raw_delivery.contains(activation.activation_secret.expose_secret()));
    assert!(!raw_delivery.contains(&activation.activation_id.to_string()));
    assert!(!raw_delivery.contains(&activation.user_id.to_string()));
    assert_eq!(activation.display_name, "Activation member");
    assert_eq!(activation.controller_origin, "https://control.test");
    assert_eq!(
        activation.bundle_signing_public_key,
        app.controller_public_key
    );

    let signing_key = SigningKey::generate(&mut OsRng);
    let request = signed_activation_request(&activation, &signing_key, 21);
    let (session, first_consume) = consume_activation_ok(&app, &request).await;
    let (replayed_session, second_consume) = consume_activation_ok(&app, &request).await;
    assert_eq!(first_consume, second_consume);
    assert_eq!(session, replayed_session);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let activation_verifier: Vec<u8> = connection
        .query_row(
            "SELECT secret_verifier FROM device_activations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let refresh_verifier: Vec<u8> = connection
        .query_row(
            "SELECT current_refresh_verifier FROM refresh_sessions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(activation_verifier.len(), 32);
    assert_eq!(refresh_verifier.len(), 32);
    let database_bytes = std::fs::read(app.database_path()).unwrap();
    assert!(!database_bytes
        .windows(activation.activation_secret.expose_secret().len())
        .any(|window| window == activation.activation_secret.expose_secret().as_bytes()));
    assert!(!database_bytes
        .windows(session.credentials.refresh_credential.expose_secret().len())
        .any(|window| window
            == session
                .credentials
                .refresh_credential
                .expose_secret()
                .as_bytes()));
}

#[tokio::test]
async fn login_and_refresh_require_idempotency_keys() {
    let app = TestApp::new();
    let account = create_account(&app, "Key-required member").await;
    let password = "key required password";
    set_password(&app, account.account.user_id, password).await;
    let login = signed_login_request(account.account.user_id, password, 26);
    let missing_login_key = post_public_json(&app, "/v1/sessions", &login).await;
    assert_eq!(missing_login_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json(missing_login_key).await["error"]["code"],
        "validation_failed"
    );
    let missing_refresh_key = post_public_json(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: Secret::new(format!("rcr1.{}.unused", Uuid::new_v4())),
        },
    )
    .await;
    assert_eq!(missing_refresh_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json(missing_refresh_key).await["error"]["code"],
        "validation_failed"
    );
}

#[tokio::test]
async fn password_login_replays_after_restart_and_concurrent_exact_retries_converge() {
    let app = TestApp::new();
    let account = create_account(&app, "Idempotent login member").await;
    let password = "idempotent login password";
    set_password(&app, account.account.user_id, password).await;
    let login = signed_login_request(account.account.user_id, password, 27);
    let key = Uuid::new_v4().to_string();
    let first = post_public_json_with_key(&app, "/v1/sessions", &login, &key).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
    let first_session: CreateDeviceSessionResponse = serde_json::from_slice(&first_bytes).unwrap();

    let app = app.restart();
    let replay = post_public_json_with_key(&app, "/v1/sessions", &login, &key).await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        first_bytes
    );

    let conflict_login = signed_login_request(account.account.user_id, password, 28);
    let conflict = post_public_json_with_key(&app, "/v1/sessions", &conflict_login, &key).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(conflict).await["error"]["code"],
        "idempotency_key_conflict"
    );

    let concurrent_login = signed_login_request(account.account.user_id, password, 29);
    let concurrent_key = Uuid::new_v4().to_string();
    let body = serde_json::to_vec(&concurrent_login).unwrap();
    let first_request = Request::post("/v1/sessions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(IDEMPOTENCY_KEY_HEADER, &concurrent_key)
        .body(Body::from(body.clone()))
        .unwrap();
    let second_request = Request::post("/v1/sessions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(IDEMPOTENCY_KEY_HEADER, &concurrent_key)
        .body(Body::from(body))
        .unwrap();
    let (first_retry, second_retry) = tokio::join!(
        app.router.clone().oneshot(first_request),
        app.router.clone().oneshot(second_request),
    );
    let first_retry = first_retry.unwrap();
    let second_retry = second_retry.unwrap();
    assert_eq!(first_retry.status(), StatusCode::CREATED);
    assert_eq!(second_retry.status(), StatusCode::CREATED);
    assert_eq!(
        first_retry.into_body().collect().await.unwrap().to_bytes(),
        second_retry.into_body().collect().await.unwrap().to_bytes()
    );

    let database_bytes = std::fs::read(app.database_path()).unwrap();
    assert!(!database_bytes
        .windows(
            first_session
                .credentials
                .refresh_credential
                .expose_secret()
                .len()
        )
        .any(|window| {
            window
                == first_session
                    .credentials
                    .refresh_credential
                    .expose_secret()
                    .as_bytes()
        }));
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM devices),
                (SELECT COUNT(*) FROM refresh_sessions),
                (SELECT COUNT(*) FROM login_idempotency_records)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (2, 2, 2));
}

#[tokio::test]
async fn refresh_reuse_revokes_family_and_bundle_etag_is_device_authenticated() {
    let app = TestApp::new();
    let account = create_account(&app, "Refresh member").await;
    let (activation, _) =
        create_device_activation_for(&app, account.account.user_id, &Uuid::new_v4().to_string())
            .await;
    let request = signed_activation_request(&activation, &SigningKey::generate(&mut OsRng), 22);
    let (session, _) = consume_activation_ok(&app, &request).await;
    let old_refresh = session.credentials.refresh_credential.clone();
    let refresh = RefreshSessionRequest {
        refresh_credential: old_refresh.clone(),
    };
    let refresh_key = Uuid::new_v4().to_string();
    let response =
        post_public_json_with_key(&app, "/v1/sessions/refresh", &refresh, &refresh_key).await;
    assert_eq!(response.status(), StatusCode::OK);
    let first_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let rotated: RefreshSessionResponse = serde_json::from_slice(&first_bytes).unwrap();
    let app = app.restart();
    let replay =
        post_public_json_with_key(&app, "/v1/sessions/refresh", &refresh, &refresh_key).await;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        first_bytes
    );

    assert_empty_bundle_etag(&app, &rotated.credentials.access_token).await;

    let second_refresh = RefreshSessionRequest {
        refresh_credential: rotated.credentials.refresh_credential.clone(),
    };
    let second_body = serde_json::to_vec(&second_refresh).unwrap();
    let first_request = Request::post("/v1/sessions/refresh")
        .header(header::CONTENT_TYPE, "application/json")
        .header(IDEMPOTENCY_KEY_HEADER, &refresh_key)
        .body(Body::from(second_body.clone()))
        .unwrap();
    let second_request = Request::post("/v1/sessions/refresh")
        .header(header::CONTENT_TYPE, "application/json")
        .header(IDEMPOTENCY_KEY_HEADER, &refresh_key)
        .body(Body::from(second_body))
        .unwrap();
    let (first_retry, second_retry) = tokio::join!(
        app.router.clone().oneshot(first_request),
        app.router.clone().oneshot(second_request),
    );
    let first_retry = first_retry.unwrap();
    let second_retry = second_retry.unwrap();
    assert_eq!(first_retry.status(), StatusCode::OK);
    assert_eq!(second_retry.status(), StatusCode::OK);
    let first_retry_bytes = first_retry.into_body().collect().await.unwrap().to_bytes();
    let second_retry_bytes = second_retry.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(first_retry_bytes, second_retry_bytes);
    let newest: RefreshSessionResponse = serde_json::from_slice(&first_retry_bytes).unwrap();

    let reuse = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &second_refresh,
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(reuse.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json(reuse).await["error"]["code"],
        "refresh_credential_reuse"
    );
    let rejected = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: newest.credentials.refresh_credential,
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
}

async fn assert_empty_bundle_etag(app: &TestApp, access_token: &Secret<String>) {
    let bundle_response = app
        .router
        .clone()
        .oneshot(
            Request::get("/v1/me/profile-bundle")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", access_token.expose_secret()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bundle_response.status(), StatusCode::OK);
    let etag = bundle_response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    let bundle: SignedProfileBundle = serde_json::from_value(json(bundle_response).await).unwrap();
    assert!(bundle.manifest.profiles.is_empty());
    let not_modified = app
        .router
        .clone()
        .oneshot(
            Request::get("/v1/me/profile-bundle")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", access_token.expose_secret()),
                )
                .header(header::IF_NONE_MATCH, &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.headers()[header::ETAG], etag);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn password_login_reset_logout_and_admin_device_revoke_are_closed() {
    let app = TestApp::new();
    let account = create_account(&app, "Password member").await;
    let password = "correct horse battery staple";
    let set = app
        .router
        .clone()
        .oneshot(
            Request::put(format!(
                "/v1/admin/accounts/{}/password",
                account.account.user_id
            ))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&SetAccountPasswordRequest {
                    new_password: Secret::new(password.to_string()),
                })
                .unwrap(),
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(set.status(), StatusCode::NO_CONTENT);

    let signing_key = SigningKey::generate(&mut OsRng);
    let mut device = unsigned_device(&signing_key, 23);
    let account_id = account.account.user_id.to_string();
    let transcript =
        device_login_proof_transcript(&account_id, "https://control.test", &device).unwrap();
    device.proof = URL_SAFE_NO_PAD
        .encode(signing_key.sign(&transcript).to_bytes())
        .parse()
        .unwrap();
    let login = CreateSessionRequest {
        account: account_id,
        password: Secret::new(password.to_string()),
        device,
    };
    let response =
        post_public_json_with_key(&app, "/v1/sessions", &login, &Uuid::new_v4().to_string()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let session: CreateDeviceSessionResponse =
        serde_json::from_value(json(response).await).unwrap();

    let logout = app
        .router
        .clone()
        .oneshot(
            Request::delete(format!("/v1/me/devices/{}/session", session.device_id))
                .header(
                    header::AUTHORIZATION,
                    format!(
                        "Bearer {}",
                        session.credentials.access_token.expose_secret()
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let logged_out_refresh = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: session.credentials.refresh_credential,
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(logged_out_refresh.status(), StatusCode::UNAUTHORIZED);

    let second_key = SigningKey::generate(&mut OsRng);
    let mut second_device = unsigned_device(&second_key, 24);
    let transcript =
        device_login_proof_transcript(&login.account, "https://control.test", &second_device)
            .unwrap();
    second_device.proof = URL_SAFE_NO_PAD
        .encode(second_key.sign(&transcript).to_bytes())
        .parse()
        .unwrap();
    let second_login = CreateSessionRequest {
        account: login.account,
        password: Secret::new(password.to_string()),
        device: second_device,
    };
    let response = post_public_json_with_key(
        &app,
        "/v1/sessions",
        &second_login,
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let session: CreateDeviceSessionResponse =
        serde_json::from_value(json(response).await).unwrap();

    let revoke = app
        .router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/devices/{}/revoke", session.device_id))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
    let rejected = post_public_json_with_key(
        &app,
        "/v1/sessions/refresh",
        &RefreshSessionRequest {
            refresh_credential: session.credentials.refresh_credential,
        },
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);

    let reset = app
        .router
        .clone()
        .oneshot(
            Request::post(format!(
                "/v1/admin/accounts/{}/session-reset",
                account.account.user_id
            ))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset.status(), StatusCode::OK);
    let reset_body = json(reset).await;
    assert_eq!(reset_body["userId"], account.account.user_id.to_string());
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let audit_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM audit_events
             WHERE event_type IN ('device.revoked', 'account.sessions-reset')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(audit_events, 2);
}

fn mark_current_endpoint_protocol_verified(app: &TestApp, node_id: NodeId, latency_ms: i64) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let candidate: (String, String, String, i64, i64, i64) = connection
        .query_row(
            "SELECT network_id, endpoint_id, address, port, applied_revision,
                    last_report_generation
             FROM node_endpoint_candidates
             WHERE node_id = ?1 AND withdrawn_at IS NULL",
            [node_id.to_string()],
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
    let now = OffsetDateTime::now_utc().unix_timestamp();
    connection
        .execute(
            "INSERT INTO endpoint_probe_attempts(
                network_id, probe_id, node_id, endpoint_id, phase, status, runner_id,
                claim_token_sha256, candidate_generation, address, port, applied_revision,
                started_at, claim_expires_at, completed_at, resolved_address, latency_ms,
                result_code
             ) VALUES (?1, ?2, ?3, ?4, 'protocol', 'succeeded', ?5, ?6, ?7, ?8,
                       ?9, ?10, ?11, ?12, ?11, '203.0.113.10', ?13,
                       'direct_protocol_connected')",
            rusqlite::params![
                candidate.0,
                Uuid::new_v4().to_string(),
                node_id.to_string(),
                candidate.1,
                Uuid::new_v4().to_string(),
                vec![3_u8; 32],
                candidate.5,
                candidate.2,
                candidate.3,
                candidate.4,
                now,
                now + 30,
                latency_ms,
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE node_endpoint_verifications
             SET status = 'verified', probe_attempts = probe_attempts + 1,
                 last_probe_at = ?1, last_success_at = ?1, latency_ms = ?2,
                 error_code = NULL, verification_expires_at = ?3, updated_at = ?1
             WHERE node_id = ?4 AND endpoint_id = ?5",
            rusqlite::params![
                now,
                latency_ms,
                now + 3_600,
                node_id.to_string(),
                candidate.1
            ],
        )
        .unwrap();
}

async fn fetch_member_bundle(
    app: &TestApp,
    access_token: &Secret<String>,
) -> (SignedProfileBundle, String) {
    let response = app
        .router
        .clone()
        .oneshot(
            Request::get("/v1/me/profile-bundle")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", access_token.expose_secret()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    let bundle = serde_json::from_value(json(response).await).unwrap();
    (bundle, etag)
}

#[tokio::test]
async fn bundle_requires_exact_applied_credential_and_current_protocol_endpoint_per_node() {
    let app = TestApp::new();
    let account = create_account(&app, "Bundle member").await;
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    let first_baseline = approve_configured_node(&app, &first).await;
    let second_baseline = approve_configured_node(&app, &second).await;
    let assigned = replace_account_nodes(
        &app,
        account.account.user_id,
        &[first.node_id, second.node_id],
    )
    .await;
    assert_eq!(assigned.status(), StatusCode::OK);
    let first_desired = fetch_desired_ok(&app, &first, first_baseline.document.revision, 230).await;
    let second_desired =
        fetch_desired_ok(&app, &second, second_baseline.document.revision, 231).await;
    report_applied_revision(
        &app,
        &first,
        first_desired.document.revision,
        61,
        [232, 233, 234],
    )
    .await;
    report_applied_revision(
        &app,
        &second,
        second_desired.document.revision,
        62,
        [235, 236, 237],
    )
    .await;
    for (index, (node, desired)) in [(&first, &first_desired), (&second, &second_desired)]
        .into_iter()
        .enumerate()
    {
        let mut current = heartbeat();
        current.heartbeat_generation =
            SequenceNumber::new(10 + i64::try_from(index).unwrap()).unwrap();
        current.revisions = RevisionProgress {
            desired_revision: Some(desired.document.revision),
            received_revision: Some(desired.document.revision),
            validated_revision: Some(desired.document.revision),
            applied_revision: Some(desired.document.revision),
        };
        current.endpoints = vec![endpoint_candidate(
            desired.document.revision,
            EndpointMode::Direct,
            EndpointSource::Manual,
            &format!("bundle-{index}.example.test"),
            443,
        )];
        assert_eq!(
            post_heartbeat(&app, node, &current, 240 + u8::try_from(index).unwrap())
                .await
                .status(),
            StatusCode::OK
        );
    }
    mark_current_endpoint_protocol_verified(&app, first.node_id, 10);

    let (activation, _) =
        create_device_activation_for(&app, account.account.user_id, &Uuid::new_v4().to_string())
            .await;
    let activation_request =
        signed_activation_request(&activation, &SigningKey::generate(&mut OsRng), 25);
    let (session, _) = consume_activation_ok(&app, &activation_request).await;
    let (partial, partial_etag) =
        fetch_member_bundle(&app, &session.credentials.access_token).await;
    assert_eq!(partial.manifest.profiles.len(), 1);
    assert_eq!(partial.manifest.profiles[0].node_id, first.node_id);

    mark_current_endpoint_protocol_verified(&app, second.node_id, 20);
    let (complete, complete_etag) =
        fetch_member_bundle(&app, &session.credentials.access_token).await;
    assert_eq!(complete.manifest.profiles.len(), 2);
    assert_ne!(partial_etag, complete_etag);
    assert!(complete
        .manifest
        .profiles
        .windows(2)
        .all(|items| items[0].node_id < items[1].node_id));
    let admin_json = serde_json::to_string(&only_account(&app).await).unwrap();
    for desired in [&first_desired, &second_desired] {
        assert!(!admin_json.contains(desired.document.users[0].vless_uuid.expose_secret()));
    }
    assert_device_revoke_rotates_assigned_credentials(
        &app,
        session.device_id,
        &[first.node_id, second.node_id],
    )
    .await;
}

async fn assert_device_revoke_rotates_assigned_credentials(
    app: &TestApp,
    device_id: DeviceId,
    node_ids: &[NodeId],
) {
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let previous_revision: i64 = connection
        .query_row("SELECT last_revision FROM networks", [], |row| row.get(0))
        .unwrap();
    let mut statement = connection
        .prepare(
            "SELECT credential_id FROM user_node_credentials
             WHERE node_id = ?1 AND status = 'active'",
        )
        .unwrap();
    let previous_credentials = node_ids
        .iter()
        .map(|node_id| {
            statement
                .query_row([node_id.to_string()], |row| row.get::<_, String>(0))
                .unwrap()
        })
        .collect::<Vec<_>>();
    drop(statement);
    drop(connection);

    let response = app
        .router
        .clone()
        .oneshot(
            Request::post(format!("/v1/admin/devices/{device_id}/revoke"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let current_revision: i64 = connection
        .query_row("SELECT last_revision FROM networks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        current_revision,
        previous_revision + i64::try_from(node_ids.len()).unwrap()
    );
    for (node_id, previous_credential) in node_ids.iter().zip(previous_credentials) {
        let old_status: String = connection
            .query_row(
                "SELECT status FROM user_node_credentials WHERE credential_id = ?1",
                [previous_credential],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_status, "revoked");
        let replacement_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM user_node_credentials
                 WHERE node_id = ?1 AND status = 'pending'",
                [node_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(replacement_count, 1);
    }
}

fn rollback_configuration(listen_port: u16, public_port: u16, target: &str) -> Value {
    serde_json::json!({
        "minAgentVersion": "0.1.0",
        "xray": {
            "listenPort": listen_port,
            "publicPort": public_port,
            "serverNames": ["rollback.example.test"],
            "target": target,
        }
    })
}

async fn report_rejected_revision(
    app: &TestApp,
    node: &SignedNode,
    revision: Revision,
    nonce_bytes: [u8; 2],
) {
    assert_eq!(
        report_result(
            app,
            node,
            revision,
            &revision_result(RevisionResultState::Received, 0, None),
            nonce_bytes[0],
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        report_result(
            app,
            node,
            revision,
            &revision_result(RevisionResultState::Rejected, 0, None),
            nonce_bytes[1],
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn single_node_rollback_is_new_idempotent_revision_with_failure_summary_and_audit() {
    let app = TestApp::new();
    let node = enroll_signed_node(&app).await;
    let source_configuration = rollback_configuration(10_440, 8_440, "source.example.test:443");
    let source = approve_and_publish(&app, &node, &source_configuration).await;
    report_applied_revision(&app, &node, source.document.revision, 81, [140, 141, 142]).await;
    let failed = publish_and_fetch_desired(
        &app,
        &node,
        &rollback_configuration(10_441, 8_441, "failed.example.test:443"),
    )
    .await;
    report_rejected_revision(&app, &node, failed.document.revision, [143, 144]).await;

    let nodes = json(admin_nodes(&app).await).await;
    let last_failure = &nodes["nodes"][0]["lastFailure"];
    assert_eq!(last_failure["revision"], failed.document.revision.get());
    assert_eq!(last_failure["state"], "rejected");
    assert_eq!(last_failure["errorCode"], "validation_failed");

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let source_artifact: String = connection
        .query_row(
            "SELECT artifact_json FROM config_revisions WHERE revision = ?1",
            [source.document.revision.get()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let rollback = OperatorNodeRollbackRequest {
        source_revision: source.document.revision,
        failed_revision: failed.document.revision,
        reason: OperatorRollbackReason::ConfigurationFailure,
    };
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE nodes SET agent_version = '0.0.9' WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .unwrap();
    drop(connection);
    let incompatible = admin_json_request_with_key(
        &app,
        "POST",
        &format!("/v1/admin/nodes/{}/rollback", node.node_id),
        serde_json::to_value(&rollback).unwrap(),
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(incompatible.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(incompatible).await["error"]["code"],
        "rollback_target_incompatible"
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    connection
        .execute(
            "UPDATE nodes SET agent_version = '0.1.0' WHERE node_id = ?1",
            [node.node_id.to_string()],
        )
        .unwrap();
    let revision_after_incompatible: i64 = connection
        .query_row("SELECT last_revision FROM networks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(revision_after_incompatible, failed.document.revision.get());
    drop(connection);
    let key = Uuid::new_v4().to_string();
    let first = admin_json_request_with_key(
        &app,
        "POST",
        &format!("/v1/admin/nodes/{}/rollback", node.node_id),
        serde_json::to_value(&rollback).unwrap(),
        &key,
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_bytes = first.into_body().collect().await.unwrap().to_bytes();
    let response: OperatorRollbackResponse = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(response.publications.len(), 1);
    let publication = &response.publications[0];
    assert_eq!(publication.node_id, node.node_id);
    assert_eq!(publication.source_revision, source.document.revision);
    assert_eq!(publication.failed_revision, failed.document.revision);
    assert!(publication.revision > failed.document.revision);

    let replay = admin_json_request_with_key(
        &app,
        "POST",
        &format!("/v1/admin/nodes/{}/rollback", node.node_id),
        serde_json::to_value(&rollback).unwrap(),
        &key,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        first_bytes
    );
    let fetched = fetch_desired_ok(&app, &node, failed.document.revision, 145).await;
    assert_eq!(fetched.document.revision, publication.revision);
    assert_eq!(fetched.document.xray, source.document.xray);
    assert_eq!(fetched.document.min_agent_version, "0.1.0");

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (String, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT artifact_json FROM config_revisions WHERE revision = ?1),
                (SELECT COUNT(*) FROM audit_events WHERE event_type = 'node.revision-failed'),
                (SELECT COUNT(*) FROM audit_events
                 WHERE event_type = 'node.operator-rollback-published')",
            [source.document.revision.get()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (source_artifact, 1, 1));
    let rollback_details: String = connection
        .query_row(
            "SELECT details_json FROM audit_events
             WHERE event_type = 'node.operator-rollback-published'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!rollback_details.contains("vlessUuid"));
    assert!(!rollback_details.contains("artifact"));
    drop(connection);

    let invalid = OperatorNodeRollbackRequest {
        source_revision: source.document.revision,
        failed_revision: publication.revision,
        reason: OperatorRollbackReason::Other,
    };
    let invalid_response = admin_json_request_with_key(
        &app,
        "POST",
        &format!("/v1/admin/nodes/{}/rollback", node.node_id),
        serde_json::to_value(invalid).unwrap(),
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(invalid_response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(invalid_response).await["error"]["code"],
        "rollback_target_invalid"
    );
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let rejected_audits: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM audit_events
             WHERE event_type = 'node.operator-rollback-rejected'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rejected_audits, 2);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn explicit_cohort_rollback_is_atomic_monotonic_and_idempotent() {
    let app = TestApp::new();
    let first = enroll_signed_node(&app).await;
    let second = enroll_signed_node(&app).await;
    let first_source = approve_and_publish(
        &app,
        &first,
        &rollback_configuration(10_450, 8_450, "first-source.example.test:443"),
    )
    .await;
    let second_source = approve_and_publish(
        &app,
        &second,
        &rollback_configuration(10_451, 8_451, "second-source.example.test:443"),
    )
    .await;
    report_applied_revision(
        &app,
        &first,
        first_source.document.revision,
        82,
        [150, 151, 152],
    )
    .await;
    report_applied_revision(
        &app,
        &second,
        second_source.document.revision,
        83,
        [153, 154, 155],
    )
    .await;
    let first_failed = publish_and_fetch_desired(
        &app,
        &first,
        &rollback_configuration(10_452, 8_452, "first-failed.example.test:443"),
    )
    .await;
    let second_failed = publish_and_fetch_desired(
        &app,
        &second,
        &rollback_configuration(10_453, 8_453, "second-failed.example.test:443"),
    )
    .await;
    report_rejected_revision(&app, &first, first_failed.document.revision, [156, 157]).await;
    report_rejected_revision(&app, &second, second_failed.document.revision, [158, 159]).await;

    let invalid_cohort = OperatorCohortRollbackRequest {
        targets: vec![
            OperatorRollbackTarget {
                node_id: first.node_id,
                source_revision: first_source.document.revision,
                failed_revision: first_failed.document.revision,
            },
            OperatorRollbackTarget {
                node_id: second.node_id,
                source_revision: first_source.document.revision,
                failed_revision: second_failed.document.revision,
            },
        ],
        reason: OperatorRollbackReason::FleetRecovery,
    };
    let invalid_response = admin_json_request_with_key(
        &app,
        "POST",
        "/v1/admin/rollbacks",
        serde_json::to_value(invalid_cohort).unwrap(),
        &Uuid::new_v4().to_string(),
    )
    .await;
    assert_eq!(invalid_response.status(), StatusCode::CONFLICT);
    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let revision_after_rejection: i64 = connection
        .query_row("SELECT last_revision FROM networks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        revision_after_rejection,
        second_failed.document.revision.get()
    );
    drop(connection);

    let request = OperatorCohortRollbackRequest {
        targets: vec![
            OperatorRollbackTarget {
                node_id: second.node_id,
                source_revision: second_source.document.revision,
                failed_revision: second_failed.document.revision,
            },
            OperatorRollbackTarget {
                node_id: first.node_id,
                source_revision: first_source.document.revision,
                failed_revision: first_failed.document.revision,
            },
        ],
        reason: OperatorRollbackReason::FleetRecovery,
    };
    let key = Uuid::new_v4().to_string();
    let first_response = admin_json_request_with_key(
        &app,
        "POST",
        "/v1/admin/rollbacks",
        serde_json::to_value(&request).unwrap(),
        &key,
    )
    .await;
    assert_eq!(first_response.status(), StatusCode::CREATED);
    let first_bytes = first_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let response: OperatorRollbackResponse = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(response.publications.len(), 2);
    assert!(response.publications[0].node_id < response.publications[1].node_id);
    assert_eq!(
        response.publications[1].revision.get(),
        response.publications[0].revision.get() + 1
    );
    assert!(response
        .publications
        .iter()
        .all(|publication| publication.revision > second_failed.document.revision));
    let replay = admin_json_request_with_key(
        &app,
        "POST",
        "/v1/admin/rollbacks",
        serde_json::to_value(&request).unwrap(),
        &key,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(
        replay.into_body().collect().await.unwrap().to_bytes(),
        first_bytes
    );

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let durable: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM config_revisions),
                (SELECT COUNT(*) FROM audit_events
                 WHERE event_type = 'node.operator-rollback-published'),
                (SELECT COUNT(*) FROM idempotency_records
                 WHERE route_id = 'v1.admin.rollbacks.create')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(durable, (6, 2, 1));
}

#[tokio::test]
async fn signed_telemetry_upload_is_idempotent_and_rejects_sequence_gaps() {
    let app = TestApp::new();
    let account = create_account(&app, "Telemetry member").await;
    let (node, _) = setup_applied_heartbeat(&app).await;
    assert_eq!(
        replace_account_nodes(&app, account.account.user_id, &[node.node_id])
            .await
            .status(),
        StatusCode::OK
    );
    let event = TelemetryEvent {
        sequence: SequenceNumber::new(1).unwrap(),
        occurred_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
        kind: TelemetryEventKind::TrafficDelta {
            user_id: account.account.user_id,
            bytes_up: Count::new(11).unwrap(),
            bytes_down: Count::new(17).unwrap(),
            connection_count: Count::new(1).unwrap(),
        },
    };
    let batch = TelemetryBatch {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        node_id: node.node_id,
        first_sequence: event.sequence,
        last_sequence: event.sequence,
        events: vec![event],
    };
    let path = format!("/v1/nodes/{}/telemetry", node.node_id);
    for _ in 0..2 {
        let request = signed_node_request(
            &node,
            "PUT",
            &path,
            serde_json::to_vec(&batch).unwrap(),
            Timestamp::from_datetime(OffsetDateTime::now_utc()),
            &fresh_nonce(),
        );
        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let acknowledgement: TelemetryBatchAcknowledgement =
            serde_json::from_value(json(response).await).unwrap();
        assert_eq!(acknowledgement.acknowledged_sequence.get(), 1);
        assert_eq!(acknowledgement.expected_sequence.get(), 2);
    }

    let mut gap = batch;
    gap.first_sequence = SequenceNumber::new(3).unwrap();
    gap.last_sequence = SequenceNumber::new(3).unwrap();
    gap.events[0].sequence = SequenceNumber::new(3).unwrap();
    let request = signed_node_request(
        &node,
        "PUT",
        &path,
        serde_json::to_vec(&gap).unwrap(),
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
        &fresh_nonce(),
    );
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json(response).await["error"]["code"],
        "telemetry_sequence_gap"
    );

    let cursor_path = format!("/v1/nodes/{}/telemetry/cursor", node.node_id);
    let response = app
        .router
        .clone()
        .oneshot(signed_node_request(
            &node,
            "GET",
            &cursor_path,
            Vec::new(),
            Timestamp::from_datetime(OffsetDateTime::now_utc()),
            &fresh_nonce(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cursor: TelemetryCursor = serde_json::from_value(json(response).await).unwrap();
    assert_eq!(cursor.acknowledged_sequence.get(), 1);

    let connection = rusqlite::Connection::open(app.database_path()).unwrap();
    let totals: (i64, i64, i64) = connection
        .query_row(
            "SELECT SUM(bytes_up), SUM(bytes_down), SUM(connection_count)
             FROM traffic_hourly_aggregates WHERE node_id = ?1 AND user_id = ?2",
            rusqlite::params![
                node.node_id.to_string(),
                account.account.user_id.to_string()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(totals, (11, 17, 1));
}
