use crate::auth::BootstrapTokenVerifier;
use crate::db::{Database, DatabaseError, NetworkRecord, SCHEMA_VERSION};
use crate::error::{ApiError, REQUEST_ID_HEADER};
use crate::protocol::RequestId;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EnrollNodeRequest,
    EnrollNodeResponse,
};
use http_body_util::BodyExt as _;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::str::FromStr;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::Instrument;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    database: Database,
    bootstrap_token: BootstrapTokenVerifier,
    controller_origin: String,
    request_timeout: Duration,
}

impl AppState {
    #[must_use]
    pub fn new(
        database: Database,
        bootstrap_token: BootstrapTokenVerifier,
        controller_origin: String,
        request_timeout: Duration,
    ) -> Self {
        Self {
            database,
            bootstrap_token,
            controller_origin,
            request_timeout,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let admin_routes = Router::new()
        .route("/v1/admin/network", get(get_network))
        .route("/v1/admin/node-invitations", post(create_node_invitation))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/nodes/enroll", post(enroll_node))
        .merge(admin_routes)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, enforce_limits))
        .layer(middleware::from_fn(request_context))
}

async fn create_node_invitation(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<(axum::http::StatusCode, Json<CreateNodeInvitationResponse>), ApiError> {
    let body: CreateNodeInvitationRequest = parse_bounded_json(request, request_id).await?;
    body.validate()
        .map_err(|_| ApiError::validation_failed(request_id))?;
    let response = state
        .database
        .create_node_invitation(body, state.controller_origin)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok((axum::http::StatusCode::CREATED, Json(response)))
}

async fn enroll_node(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<(axum::http::StatusCode, Json<EnrollNodeResponse>), ApiError> {
    let body: EnrollNodeRequest = parse_bounded_json(request, request_id).await?;
    body.validate()
        .map_err(|_| ApiError::validation_failed(request_id))?;
    let response = state
        .database
        .enroll_node(body)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    let status = if response.created {
        axum::http::StatusCode::CREATED
    } else {
        axum::http::StatusCode::OK
    };
    Ok((status, Json(response.response)))
}

async fn parse_bounded_json<T>(request: Request, request_id: RequestId) -> Result<T, ApiError>
where
    T: DeserializeOwned,
{
    let mut body = request.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| ApiError::validation_failed(request_id))?;
        if let Ok(data) = frame.into_data() {
            let next_length = bytes
                .len()
                .checked_add(data.len())
                .ok_or_else(|| ApiError::body_too_large(request_id))?;
            if next_length > MAX_REQUEST_BODY_BYTES {
                return Err(ApiError::body_too_large(request_id));
            }
            bytes.extend_from_slice(&data);
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| ApiError::validation_failed(request_id))
}

fn database_api_error(error: DatabaseError, request_id: RequestId) -> ApiError {
    match error {
        DatabaseError::Validation(_) => ApiError::validation_failed(request_id),
        DatabaseError::InvitationInvalid => ApiError::invitation_invalid(request_id),
        DatabaseError::InvitationExpired => ApiError::invitation_expired(request_id),
        DatabaseError::InvitationConsumed => ApiError::invitation_consumed(request_id),
        DatabaseError::InvitationCancelled => ApiError::invitation_cancelled(request_id),
        DatabaseError::InvalidEnrollmentProof => ApiError::signature_invalid(request_id),
        other => {
            tracing::error!(request_id = %request_id, error = %other, "database request failed");
            ApiError::internal(request_id)
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    schema_version: i64,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        schema_version: SCHEMA_VERSION,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkResponse {
    network_id: String,
    display_name: String,
    status: String,
    last_revision: i64,
    controller_epoch: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<NetworkRecord> for NetworkResponse {
    type Error = time::error::ComponentRange;

    fn try_from(record: NetworkRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            network_id: record.network_id,
            display_name: record.display_name,
            status: record.status,
            last_revision: record.last_revision,
            controller_epoch: record.controller_epoch,
            created_at: OffsetDateTime::from_unix_timestamp(record.created_at)?
                .format(&Rfc3339)
                .expect("RFC 3339 formatting is infallible for a valid timestamp"),
            updated_at: OffsetDateTime::from_unix_timestamp(record.updated_at)?
                .format(&Rfc3339)
                .expect("RFC 3339 formatting is infallible for a valid timestamp"),
        })
    }
}

async fn get_network(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<NetworkResponse>, ApiError> {
    let network = state.database.network().await.map_err(|error| {
        tracing::error!(request_id = %request_id, error = %error, "database request failed");
        ApiError::internal(request_id)
    })?;
    let response = NetworkResponse::try_from(network).map_err(|error| {
        tracing::error!(request_id = %request_id, error = %error, "stored timestamp is invalid");
        ApiError::internal(request_id)
    })?;
    Ok(Json(response))
}

async fn require_admin(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let request_id = request_id(&request);
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if !token.is_some_and(|value| state.bootstrap_token.verify(value)) {
        return ApiError::authentication_failed(request_id).into_response();
    }

    next.run(request).await
}

async fn enforce_limits(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let request_id = request_id(&request);
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if content_length.is_some_and(|length| length > MAX_REQUEST_BODY_BYTES as u64) {
        return ApiError::body_too_large(request_id).into_response();
    }

    match tokio::time::timeout(state.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::timeout(request_id).into_response(),
    }
}

async fn request_context(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| RequestId::from_str(value).ok())
        .unwrap_or_default();
    request.extensions_mut().insert(request_id);

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path
    );
    let started = Instant::now();
    let mut response = async move {
        let response = next.run(request).await;
        tracing::info!(
            status = response.status().as_u16(),
            elapsed_ms = started.elapsed().as_millis(),
            "request completed"
        );
        response
    }
    .instrument(span)
    .await;

    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

async fn not_found(Extension(request_id): Extension<RequestId>) -> ApiError {
    ApiError::not_found(request_id)
}

async fn method_not_allowed(Extension(request_id): Extension<RequestId>) -> ApiError {
    ApiError::method_not_allowed(request_id)
}

fn request_id(request: &Request) -> RequestId {
    request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::NetworkResponse;
    use crate::db::NetworkRecord;

    #[test]
    fn network_timestamps_are_rfc3339_utc() {
        let response = NetworkResponse::try_from(NetworkRecord {
            network_id: "network".to_string(),
            display_name: "Friends".to_string(),
            status: "active".to_string(),
            last_revision: 0,
            controller_epoch: "epoch".to_string(),
            created_at: 0,
            updated_at: 1,
        })
        .unwrap();

        assert_eq!(response.created_at, "1970-01-01T00:00:00Z");
        assert_eq!(response.updated_at, "1970-01-01T00:00:01Z");
    }
}
