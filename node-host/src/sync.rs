use crate::enrollment::{control_http_client, read_bounded_response};
use crate::{
    build_status, load_sync_registration, migrate, open_database, parse_controller, unix_timestamp,
    DataDirLock, HostStatus, Identity,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::Nonce;
use control_protocol::error::ErrorEnvelope;
use control_protocol::id::{SequenceNumber, Timestamp};
use control_protocol::node::{NodeHeartbeat, NodeRuntimeState, RevisionProgress};
use control_protocol::request_auth::{NodeRequestAuthHeaders, NodeRequestSigningInput};
use rand_core::{OsRng, RngCore as _};
use reqwest::{Method, StatusCode};
use rusqlite::{params, Connection};
use std::path::Path;
use std::str::FromStr as _;
use time::OffsetDateTime;
use url::Url;

const NONCE_BYTES: usize = 32;
const NODE_ID_HEADER: &str = "X-Node-Id";
const NODE_KEY_ID_HEADER: &str = "X-Node-Key-Id";
const NODE_TIMESTAMP_HEADER: &str = "X-Node-Timestamp";
const NODE_NONCE_HEADER: &str = "X-Node-Nonce";
const NODE_SIGNATURE_HEADER: &str = "X-Node-Signature";

/// Performs one authenticated heartbeat and desired-state fetch.
///
/// This phase intentionally accepts only `204 No Content` from the desired
/// endpoint. The shared protocol does not yet define desired-state signature
/// verification, so a document cannot be accepted safely.
///
/// # Errors
///
/// Returns an error when the host is not enrolled, credentials are invalid,
/// request signing or transport fails, or the controller returns anything
/// other than an acknowledged heartbeat followed by no desired state.
pub async fn sync_once(data_dir: &Path) -> Result<HostStatus> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let controller_value: String = connection
        .query_row(
            "SELECT controller_url FROM host_config WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .context("node host is not initialized")?;
    let controller = parse_controller(&controller_value)?;
    let identity = Identity::load(data_dir)?;
    let registration = load_sync_registration(&connection)?;
    let sync_state = crate::load_sync_status(&connection)?;
    if sync_state.desired_revision_cursor != 0 {
        bail!("this node host version cannot synchronize a non-zero desired revision cursor");
    }

    let heartbeat = initial_heartbeat()?;
    let heartbeat_body =
        serde_json::to_vec(&heartbeat).context("failed to serialize node heartbeat")?;
    let heartbeat_target = format!("/v1/nodes/{}/heartbeat", registration.node);
    let client = control_http_client().context("failed to initialize sync HTTP client")?;
    let heartbeat_response = send_signed_request(
        &client,
        &controller,
        Method::POST,
        &heartbeat_target,
        heartbeat_body,
        &registration,
        &identity,
    )
    .await
    .context("controller heartbeat request failed")?;
    let heartbeat_status = heartbeat_response.status();
    let heartbeat_response_body = read_bounded_response(heartbeat_response).await?;
    if !heartbeat_status.is_success() {
        return Err(controller_error(
            "heartbeat",
            heartbeat_status,
            &heartbeat_response_body,
        ));
    }
    if !matches!(heartbeat_status, StatusCode::OK | StatusCode::NO_CONTENT) {
        bail!("controller returned unexpected heartbeat success status {heartbeat_status}");
    }
    persist_heartbeat_success(&connection)?;

    let desired_target = format!("/v1/nodes/{}/desired?afterRevision=0", registration.node);
    let desired_response = send_signed_request(
        &client,
        &controller,
        Method::GET,
        &desired_target,
        Vec::new(),
        &registration,
        &identity,
    )
    .await
    .context("controller desired-state request failed")?;
    let desired_status = desired_response.status();
    let desired_body = read_bounded_response(desired_response).await?;
    match desired_status {
        StatusCode::NO_CONTENT if desired_body.is_empty() => {
            persist_sync_success(&connection)?;
        }
        StatusCode::NO_CONTENT => {
            bail!("controller returned a body with no desired state");
        }
        StatusCode::OK => {
            bail!("controller returned desired state that this node host cannot verify");
        }
        status if !status.is_success() => {
            return Err(controller_error("desired-state", status, &desired_body));
        }
        _ => bail!("controller returned unexpected desired-state success status {desired_status}"),
    }

    build_status(&connection, controller, &identity)
}

fn initial_heartbeat() -> Result<NodeHeartbeat> {
    let heartbeat = NodeHeartbeat {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        xray_version: None,
        state: NodeRuntimeState::Idle,
        revisions: RevisionProgress {
            desired_revision: None,
            received_revision: None,
            validated_revision: None,
            applied_revision: None,
        },
        provider_paused: false,
        endpoints: Vec::new(),
        telemetry_cursor: SequenceNumber::new(0).context("zero telemetry cursor must be valid")?,
    };
    heartbeat
        .validate()
        .context("generated node heartbeat is invalid")?;
    Ok(heartbeat)
}

async fn send_signed_request(
    client: &reqwest::Client,
    controller: &Url,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
    registration: &crate::SyncRegistration,
    identity: &Identity,
) -> Result<reqwest::Response> {
    let method_name = method.as_str().to_owned();
    let is_post = method == Method::POST;
    let signing_input = NodeRequestSigningInput::from_body(&method_name, path_and_query, &body)
        .context("failed to construct signed request input")?;
    let timestamp = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let nonce = fresh_nonce()?;
    let transcript = signing_input
        .transcript(timestamp, &nonce, registration.controller_instance)
        .context("failed to encode signed request transcript")?;
    let signature = identity.sign(&transcript)?;
    let headers = NodeRequestAuthHeaders::new(
        registration.node,
        registration.key,
        timestamp,
        nonce,
        signature,
    );
    let endpoint: Url = format!(
        "{}{}",
        controller.as_str().trim_end_matches('/'),
        path_and_query
    )
    .parse()
    .context("failed to construct controller endpoint")?;

    let mut request = client
        .request(method, endpoint)
        .header(NODE_ID_HEADER, headers.node_id().to_string())
        .header(NODE_KEY_ID_HEADER, headers.key_id().to_string())
        .header(NODE_TIMESTAMP_HEADER, headers.timestamp().to_string())
        .header(NODE_NONCE_HEADER, headers.nonce().as_str())
        .header(NODE_SIGNATURE_HEADER, headers.signature().as_str());
    if is_post {
        request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
    }
    request
        .body(body)
        .send()
        .await
        .context("signed controller request failed")
}

fn fresh_nonce() -> Result<Nonce> {
    let mut bytes = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    Nonce::from_str(&URL_SAFE_NO_PAD.encode(bytes)).context("failed to encode request nonce")
}

fn persist_heartbeat_success(connection: &Connection) -> Result<()> {
    connection.execute(
        "UPDATE control_sync_state SET last_heartbeat_at = ?1 WHERE singleton = 1",
        params![unix_timestamp()?],
    )?;
    Ok(())
}

fn persist_sync_success(connection: &Connection) -> Result<()> {
    connection.execute(
        "UPDATE control_sync_state SET last_sync_at = ?1 WHERE singleton = 1",
        params![unix_timestamp()?],
    )?;
    Ok(())
}

fn controller_error(operation: &str, status: StatusCode, body: &[u8]) -> anyhow::Error {
    if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(body) {
        anyhow::anyhow!(
            "controller rejected {operation} with {} (request {})",
            envelope.error.code,
            envelope.error.request_id
        )
    } else {
        anyhow::anyhow!("controller rejected {operation} with HTTP {status}")
    }
}
