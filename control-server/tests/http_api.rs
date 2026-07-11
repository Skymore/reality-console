use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use control_server::{build_router, AppState, Database, ServiceConfig};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "integration-bootstrap-token-with-enough-entropy";

struct TestApp {
    _temp: TempDir,
    router: axum::Router,
}

impl TestApp {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let config = ServiceConfig::for_test(temp.path().join("control.sqlite3"), TOKEN).unwrap();
        let database = Database::open(&config.database_path, &config.network_display_name).unwrap();
        let state = AppState::new(database, config.bootstrap_token, config.request_timeout);
        Self {
            _temp: temp,
            router: build_router(state),
        }
    }
}

async fn json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
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
