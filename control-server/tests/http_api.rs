use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, X25519PublicKey};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, EnrollmentInvitation,
};
use control_protocol::id::{
    ControllerInstanceId, NodeId, NodeKeyId, Revision, SequenceNumber, Timestamp,
};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EndpointMode, EndpointStatus,
    EnrollNodeRequest, EnrollNodeResponse, NodeCapability, NodeEndpointStatus, NodeHeartbeat,
    NodeRuntimeState, ProviderConsent, RevisionProgress,
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
    let revision = Revision::new(4).unwrap();
    NodeHeartbeat {
        agent_version: "0.2.0".to_string(),
        xray_version: Some("26.7.11".to_string()),
        state: NodeRuntimeState::Serving,
        revisions: RevisionProgress {
            desired_revision: Some(revision),
            received_revision: Some(revision),
            validated_revision: Some(revision),
            applied_revision: Some(revision),
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
    let stored: (String, String, String, i64, i64, i64) = connection
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
        ("pending".into(), "0.2.0".into(), "26.7.11".into(), 4, 9, 0)
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

    let revision = Revision::new(3).unwrap();
    let mut regressed = heartbeat();
    regressed.revisions = RevisionProgress {
        desired_revision: Some(revision),
        received_revision: Some(revision),
        validated_revision: Some(revision),
        applied_revision: Some(revision),
    };
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
    let stored: (String, i64, i64) = connection
        .query_row(
            "SELECT status, applied_revision, telemetry_cursor FROM nodes WHERE node_id = ?1",
            [node.node_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored, ("pending".to_string(), 4, 9));
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
