use crate::auth::BootstrapTokenVerifier;
use crate::db::{
    AuthenticatedNode, Database, DatabaseError, NetworkRecord, NodeLifecycleAction,
    NodeSummaryRecord, SCHEMA_VERSION,
};
use crate::desired::DesiredStateConfigurationDraft;
use crate::error::{ApiError, REQUEST_ID_HEADER};
use crate::protocol::RequestId;
use axum::body::Body;
use axum::extract::{Extension, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use control_protocol::account::{
    AccountSummary, CreateAccountRequest, ReplaceAccountNodesRequest, SetAccountStatusRequest,
};
use control_protocol::id::{NodeId, Revision, Timestamp, UserId};
use control_protocol::idempotency::{IdempotencyKey, IDEMPOTENCY_KEY_HEADER};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EnrollNodeRequest,
    EnrollNodeResponse, NodeCapability, NodeHeartbeat, RevisionResult, SignedDesiredState,
    SignedNodeHeartbeatStatus,
};
use control_protocol::request_auth::{NodeRequestAuthHeaders, NodeRequestSigningInput};
use http_body_util::BodyExt as _;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::str::FromStr;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::Instrument;

const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
const CANONICAL_UUID_LENGTH: usize = 36;

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
        .route("/v1/admin/nodes", get(get_nodes))
        .route("/v1/admin/accounts", get(get_accounts).post(create_account))
        .route(
            "/v1/admin/accounts/{user_id}/nodes",
            put(replace_account_nodes),
        )
        .route(
            "/v1/admin/accounts/{user_id}/status",
            put(set_account_status),
        )
        .route("/v1/admin/node-invitations", post(create_node_invitation))
        .route("/v1/admin/nodes/{node_id}/approve", post(approve_node))
        .route("/v1/admin/nodes/{node_id}/disable", post(disable_node))
        .route("/v1/admin/nodes/{node_id}/revoke", post(revoke_node))
        .route(
            "/v1/admin/nodes/{node_id}/reconcile",
            put(reconcile_node_desired_state),
        )
        .route(
            "/v1/admin/nodes/{node_id}/desired-state",
            post(publish_desired_state),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));
    let authenticated_node_routes = Router::new()
        .route("/v1/nodes/{node_id}/heartbeat", post(node_heartbeat))
        .route("/v1/nodes/{node_id}/desired", get(fetch_desired_state))
        .route(
            "/v1/nodes/{node_id}/revisions/{revision}/result",
            put(report_revision_result),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate_node,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/nodes/enroll", post(enroll_node))
        .merge(authenticated_node_routes)
        .merge(admin_routes)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, enforce_limits))
        .layer(middleware::from_fn(request_context))
}

#[derive(Clone)]
struct SignedBody(Vec<u8>);

async fn authenticate_node(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request_id(&request);
    let Ok(headers) = node_auth_headers(request.headers()) else {
        return ApiError::authentication_failed(request_id).into_response();
    };
    let method = request.method().as_str().to_owned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let (mut parts, body) = request.into_parts();
    let body = match read_bounded_body(body, request_id).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let Ok(input) = NodeRequestSigningInput::from_body(&method, &path_and_query, &body) else {
        return ApiError::authentication_failed(request_id).into_response();
    };
    let authenticated = match state
        .database
        .authenticate_node_request(headers, input)
        .await
    {
        Ok(authenticated) => authenticated,
        Err(error) => return database_api_error(error, request_id).into_response(),
    };

    parts.extensions.insert(authenticated);
    parts.extensions.insert(SignedBody(body));
    next.run(Request::from_parts(parts, Body::empty())).await
}

fn node_auth_headers(headers: &HeaderMap) -> Result<NodeRequestAuthHeaders, ()> {
    let node_id = single_header(headers, "x-node-id")?;
    let key_id = single_header(headers, "x-node-key-id")?;
    let timestamp = single_header(headers, "x-node-timestamp")?;
    let nonce = single_header(headers, "x-node-nonce")?;
    let signature = single_header(headers, "x-node-signature")?;
    NodeRequestAuthHeaders::parse(node_id, key_id, timestamp, nonce, signature).map_err(|_| ())
}

fn single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map_err(|_| ())
}

async fn node_heartbeat(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
    Extension(authenticated): Extension<AuthenticatedNode>,
    Extension(body): Extension<SignedBody>,
) -> Result<Json<SignedNodeHeartbeatStatus>, ApiError> {
    if path_node_id != authenticated.node_id.to_string() {
        return Err(ApiError::authentication_failed(request_id));
    }
    let heartbeat: NodeHeartbeat =
        serde_json::from_slice(&body.0).map_err(|_| ApiError::validation_failed(request_id))?;
    heartbeat
        .validate()
        .map_err(|_| ApiError::validation_failed(request_id))?;
    let status = state
        .database
        .record_heartbeat(authenticated.node_id, heartbeat)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(Json(status))
}

async fn fetch_desired_state(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
    Extension(authenticated): Extension<AuthenticatedNode>,
    uri: Uri,
) -> Result<Response, ApiError> {
    if path_node_id != authenticated.node_id.to_string() {
        return Err(ApiError::authentication_failed(request_id));
    }
    let after_revision =
        parse_after_revision(uri.query()).ok_or_else(|| ApiError::validation_failed(request_id))?;
    let desired = state
        .database
        .desired_state_after(authenticated.node_id, after_revision)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(match desired {
        Some(desired) => Json(desired).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

fn parse_after_revision(query: Option<&str>) -> Option<i64> {
    let value = query?.strip_prefix("afterRevision=")?;
    if value.is_empty() || value.len() > 19 || value.contains('&') {
        return None;
    }
    let revision = value.parse::<i64>().ok()?;
    (revision >= 0 && revision.to_string() == value).then_some(revision)
}

async fn report_revision_result(
    State(state): State<AppState>,
    Path((path_node_id, path_revision)): Path<(String, String)>,
    Extension(request_id): Extension<RequestId>,
    Extension(authenticated): Extension<AuthenticatedNode>,
    Extension(body): Extension<SignedBody>,
) -> Result<StatusCode, ApiError> {
    if path_node_id != authenticated.node_id.to_string() {
        return Err(ApiError::authentication_failed(request_id));
    }
    let revision = parse_revision(&path_revision).ok_or_else(|| ApiError::not_found(request_id))?;
    let result: RevisionResult =
        serde_json::from_slice(&body.0).map_err(|_| ApiError::validation_failed(request_id))?;
    result
        .validate(revision)
        .map_err(|_| ApiError::validation_failed(request_id))?;
    state
        .database
        .record_revision_result(authenticated.node_id, revision, result)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(StatusCode::NO_CONTENT)
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
    let bytes = read_bounded_body(request.into_body(), request_id).await?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::validation_failed(request_id))
}

async fn read_bounded_body(mut body: Body, request_id: RequestId) -> Result<Vec<u8>, ApiError> {
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
    Ok(bytes)
}

fn database_api_error(error: DatabaseError, request_id: RequestId) -> ApiError {
    match error {
        DatabaseError::Validation(_) => ApiError::validation_failed(request_id),
        DatabaseError::InvitationInvalid => ApiError::invitation_invalid(request_id),
        DatabaseError::InvitationExpired => ApiError::invitation_expired(request_id),
        DatabaseError::InvitationConsumed => ApiError::invitation_consumed(request_id),
        DatabaseError::InvitationCancelled => ApiError::invitation_cancelled(request_id),
        DatabaseError::InvalidEnrollmentProof | DatabaseError::InvalidNodeRequestSignature => {
            ApiError::signature_invalid(request_id)
        }
        DatabaseError::NodeAuthenticationFailed => ApiError::authentication_failed(request_id),
        DatabaseError::NodeRevoked => ApiError::node_revoked(request_id),
        DatabaseError::NodeRequestClockSkew => ApiError::clock_skew(request_id),
        DatabaseError::NodeRequestNonceReplayed => ApiError::nonce_replayed(request_id),
        DatabaseError::NodeProgressRegressed | DatabaseError::NodeHeartbeatStale => {
            ApiError::state_stale(request_id)
        }
        DatabaseError::NodeProgressConflict
        | DatabaseError::NodeHeartbeatConflict
        | DatabaseError::EndpointCandidateConflict
        | DatabaseError::EndpointCandidateRevisionConflict
        | DatabaseError::DesiredStatePublicationConflict { .. } => {
            ApiError::state_conflict(request_id)
        }
        DatabaseError::NodeNotFound | DatabaseError::RevisionTargetNotFound => {
            ApiError::not_found(request_id)
        }
        DatabaseError::AccountNotFound => ApiError::not_found(request_id),
        DatabaseError::IdempotencyKeyConflict => ApiError::idempotency_key_conflict(request_id),
        DatabaseError::RevisionResultConflict => ApiError::invalid_state_transition(request_id),
        DatabaseError::NodeLifecycleConflict { .. }
        | DatabaseError::AccountLifecycleConflict { .. }
        | DatabaseError::NodeUnavailableForAssignment { .. }
        | DatabaseError::AccountAssignmentConflict { .. }
        | DatabaseError::NodeConfigurationMissing => ApiError::conflict(request_id),
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
            created_at: format_timestamp(record.created_at)?,
            updated_at: format_timestamp(record.updated_at)?,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeListResponse {
    nodes: Vec<NodeSummaryResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountListResponse {
    accounts: Vec<AccountSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesiredStatePublicationResponse {
    node_id: NodeId,
    revision: Revision,
    schema_version: u16,
    created_at: Timestamp,
    user_count: usize,
    created: bool,
}

impl DesiredStatePublicationResponse {
    fn from_desired(desired: &SignedDesiredState, created: bool) -> Self {
        Self {
            node_id: desired.document.node_id,
            revision: desired.document.revision,
            schema_version: desired.document.schema_version,
            created_at: desired.document.created_at,
            user_count: desired.document.users.len(),
            created,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeSummaryResponse {
    node_id: NodeId,
    network_id: String,
    display_name: String,
    status: String,
    platform: String,
    agent_version: String,
    xray_version: Option<String>,
    capabilities: Vec<NodeCapability>,
    provider_consent: ProviderConsentResponse,
    last_seen_at: Option<String>,
    runtime_state: Option<String>,
    provider_paused: bool,
    revisions: NodeRevisionResponse,
    telemetry_cursor: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderConsentResponse {
    policy_version: String,
    host_owner_consented: bool,
    exit_ip_disclosure_accepted: bool,
    router_mapping_accepted: bool,
    accepted_at: String,
}

#[derive(Serialize)]
struct NodeRevisionResponse {
    #[serde(rename = "desiredRevision")]
    desired: Option<i64>,
    #[serde(rename = "receivedRevision")]
    received: Option<i64>,
    #[serde(rename = "validatedRevision")]
    validated: Option<i64>,
    #[serde(rename = "appliedRevision")]
    applied: Option<i64>,
}

impl TryFrom<NodeSummaryRecord> for NodeSummaryResponse {
    type Error = time::error::ComponentRange;

    fn try_from(record: NodeSummaryRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            node_id: record.node_id,
            network_id: record.network_id,
            display_name: record.display_name,
            status: record.status,
            platform: record.platform,
            agent_version: record.agent_version,
            xray_version: record.xray_version,
            capabilities: record.capabilities,
            provider_consent: ProviderConsentResponse {
                policy_version: record.provider_consent.policy_version,
                host_owner_consented: record.provider_consent.host_owner,
                exit_ip_disclosure_accepted: record.provider_consent.exit_ip,
                router_mapping_accepted: record.provider_consent.router_mapping,
                accepted_at: format_timestamp(record.provider_consent.accepted_at)?,
            },
            last_seen_at: record.last_seen_at.map(format_timestamp).transpose()?,
            runtime_state: record.runtime_state,
            provider_paused: record.provider_paused,
            revisions: NodeRevisionResponse {
                desired: record.desired_revision,
                received: record.received_revision,
                validated: record.validated_revision,
                applied: record.applied_revision,
            },
            telemetry_cursor: record.telemetry_cursor,
            created_at: format_timestamp(record.created_at)?,
            updated_at: format_timestamp(record.updated_at)?,
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

async fn get_nodes(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<NodeListResponse>, ApiError> {
    let records = state
        .database
        .list_nodes()
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    let nodes = records
        .into_iter()
        .map(NodeSummaryResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            tracing::error!(request_id = %request_id, error = %error, "stored timestamp is invalid");
            ApiError::internal(request_id)
        })?;
    Ok(Json(NodeListResponse { nodes }))
}

async fn get_accounts(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Result<Json<AccountListResponse>, ApiError> {
    let accounts = state
        .database
        .list_accounts()
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(Json(AccountListResponse { accounts }))
}

async fn create_account(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<(StatusCode, Json<AccountSummary>), ApiError> {
    let idempotency_key = parse_idempotency_key(request.headers(), request_id)?;
    let request: CreateAccountRequest = parse_bounded_json(request, request_id).await?;
    let account = state
        .database
        .create_account(request, idempotency_key)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok((StatusCode::CREATED, Json(account)))
}

async fn replace_account_nodes(
    State(state): State<AppState>,
    Path(path_user_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<Json<AccountSummary>, ApiError> {
    let user_id = parse_user_id(&path_user_id).ok_or_else(|| ApiError::not_found(request_id))?;
    let request: ReplaceAccountNodesRequest = parse_bounded_json(request, request_id).await?;
    let account = state
        .database
        .replace_account_nodes(user_id, request)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(Json(account))
}

async fn set_account_status(
    State(state): State<AppState>,
    Path(path_user_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<Json<AccountSummary>, ApiError> {
    let user_id = parse_user_id(&path_user_id).ok_or_else(|| ApiError::not_found(request_id))?;
    let request: SetAccountStatusRequest = parse_bounded_json(request, request_id).await?;
    let account = state
        .database
        .set_account_status(user_id, request.status)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(Json(account))
}

async fn publish_desired_state(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
    request: Request,
) -> Result<(StatusCode, Json<DesiredStatePublicationResponse>), ApiError> {
    let node_id = parse_node_id(&path_node_id).ok_or_else(|| ApiError::not_found(request_id))?;
    let draft: DesiredStateConfigurationDraft = parse_bounded_json(request, request_id).await?;
    let desired = state
        .database
        .publish_desired_state(node_id, draft)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    let response = DesiredStatePublicationResponse::from_desired(&desired, true);
    Ok((StatusCode::CREATED, Json(response)))
}

async fn reconcile_node_desired_state(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
) -> Result<(StatusCode, Json<DesiredStatePublicationResponse>), ApiError> {
    let node_id = parse_node_id(&path_node_id).ok_or_else(|| ApiError::not_found(request_id))?;
    let result = state
        .database
        .reconcile_node_desired_state(node_id)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    let status = if result.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let response = DesiredStatePublicationResponse::from_desired(&result.desired, result.created);
    Ok((status, Json(response)))
}

async fn approve_node(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, ApiError> {
    apply_node_lifecycle(
        &state,
        &path_node_id,
        NodeLifecycleAction::Approve,
        request_id,
    )
    .await
}

async fn disable_node(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, ApiError> {
    apply_node_lifecycle(
        &state,
        &path_node_id,
        NodeLifecycleAction::Disable,
        request_id,
    )
    .await
}

async fn revoke_node(
    State(state): State<AppState>,
    Path(path_node_id): Path<String>,
    Extension(request_id): Extension<RequestId>,
) -> Result<StatusCode, ApiError> {
    apply_node_lifecycle(
        &state,
        &path_node_id,
        NodeLifecycleAction::Revoke,
        request_id,
    )
    .await
}

async fn apply_node_lifecycle(
    state: &AppState,
    path_node_id: &str,
    action: NodeLifecycleAction,
    request_id: RequestId,
) -> Result<StatusCode, ApiError> {
    let node_id = parse_node_id(path_node_id).ok_or_else(|| ApiError::not_found(request_id))?;
    state
        .database
        .transition_node(node_id, action)
        .await
        .map_err(|error| database_api_error(error, request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

fn parse_node_id(value: &str) -> Option<NodeId> {
    if value.len() != CANONICAL_UUID_LENGTH {
        return None;
    }
    value.parse().ok()
}

fn parse_user_id(value: &str) -> Option<UserId> {
    if value.len() != CANONICAL_UUID_LENGTH {
        return None;
    }
    value.parse().ok()
}

fn parse_idempotency_key(
    headers: &HeaderMap,
    request_id: RequestId,
) -> Result<IdempotencyKey, ApiError> {
    headers
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| ApiError::validation_failed(request_id))
}

fn parse_revision(value: &str) -> Option<Revision> {
    if value.is_empty() || value.len() > 19 {
        return None;
    }
    let parsed = value.parse::<i64>().ok()?;
    (parsed.to_string() == value)
        .then(|| Revision::new(parsed).ok())
        .flatten()
}

fn format_timestamp(value: i64) -> Result<String, time::error::ComponentRange> {
    Ok(OffsetDateTime::from_unix_timestamp(value)?
        .format(&Rfc3339)
        .expect("RFC 3339 formatting is infallible for a valid timestamp"))
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
