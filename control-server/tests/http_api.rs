use axum::body::{Body, Bytes};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, X25519PublicKey};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, EnrollmentInvitation,
};
use control_protocol::id::Timestamp;
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EnrollNodeRequest,
    EnrollNodeResponse, NodeCapability, ProviderConsent,
};
use control_server::{build_router, AppState, Database, ServiceConfig};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use futures_util::stream;
use http_body_util::BodyExt;
use rand_core::OsRng;
use serde_json::Value;
use std::convert::Infallible;
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
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_public_key =
        Ed25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()))
            .unwrap();
    let encryption_public_key =
        X25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode([42_u8; 32])).unwrap();
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
    (request, transcript)
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
