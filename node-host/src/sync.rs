use crate::enrollment::{control_http_client, read_bounded_response};
use crate::{
    build_status, load_sync_registration, migrate, open_database, parse_controller, unix_timestamp,
    DataDirLock, HostStatus, Identity, SyncRegistration,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Nonce, Sha256Digest};
use control_protocol::desired::{desired_state_transcript, verify_desired_state_signature};
use control_protocol::error::ErrorEnvelope;
use control_protocol::id::{Revision, SequenceNumber, Timestamp};
use control_protocol::node::{
    NodeHeartbeat, NodeRuntimeState, RevisionProgress, RevisionResult, RevisionResultState,
    SignedDesiredState,
};
use control_protocol::request_auth::{NodeRequestAuthHeaders, NodeRequestSigningInput};
use rand_core::{OsRng, RngCore as _};
use reqwest::{Method, StatusCode};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::str::FromStr as _;
use time::OffsetDateTime;
use url::Url;

const NONCE_BYTES: usize = 32;
const SUPPORTED_DESIRED_SCHEMAS: &[u16] =
    control_protocol::version::SUPPORTED_DESIRED_STATE_SCHEMA_VERSIONS;
const MAX_PENDING_REPORTS_PER_SYNC: i64 = 64;
const NODE_ID_HEADER: &str = "X-Node-Id";
const NODE_KEY_ID_HEADER: &str = "X-Node-Key-Id";
const NODE_TIMESTAMP_HEADER: &str = "X-Node-Timestamp";
const NODE_NONCE_HEADER: &str = "X-Node-Nonce";
const NODE_SIGNATURE_HEADER: &str = "X-Node-Signature";

#[derive(Debug, Clone, Copy)]
enum ReportScope {
    ReceivedFor(Revision),
    Revision(Revision),
    All,
}

/// Performs one authenticated heartbeat and desired-state synchronization cycle.
///
/// A verified desired-state envelope is durably recorded before the node reports
/// `received`. Failed reports remain queued and are retried before the next
/// heartbeat, so a transport interruption cannot lose lifecycle progress.
///
/// # Errors
///
/// Returns an error when local state is inconsistent, the host is not enrolled,
/// a controller artifact fails identity/signature checks, or any signed control
/// request is rejected.
pub async fn sync_once(data_dir: &Path) -> Result<HostStatus> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    sync_once_locked(data_dir, NodeRuntimeState::Idle).await
}

pub(crate) async fn sync_once_locked(
    data_dir: &Path,
    runtime_state: NodeRuntimeState,
) -> Result<HostStatus> {
    sync_once_locked_with_runtime_probe(data_dir, || Ok(runtime_state)).await
}

pub(crate) async fn sync_once_locked_with_runtime_probe<F>(
    data_dir: &Path,
    mut runtime_probe: F,
) -> Result<HostStatus>
where
    F: FnMut() -> Result<NodeRuntimeState>,
{
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
    let client = control_http_client().context("failed to initialize sync HTTP client")?;

    resume_local_state(
        data_dir,
        &client,
        &controller,
        &mut connection,
        &registration,
        &identity,
    )
    .await?;
    let sync_state = crate::load_sync_status(&connection)?;
    // Observe the managed child immediately before constructing the heartbeat;
    // earlier network/report work may have taken long enough for it to exit.
    let runtime_state = runtime_probe()?;
    send_heartbeat(
        &client,
        &controller,
        &connection,
        &registration,
        &identity,
        sync_state.desired_revision_cursor,
        runtime_state,
    )
    .await?;
    fetch_and_process_desired(
        data_dir,
        &client,
        &controller,
        &mut connection,
        &registration,
        &identity,
        sync_state.desired_revision_cursor,
    )
    .await?;

    persist_sync_success(&connection)?;
    build_status(&connection, data_dir, controller, &identity)
}

async fn resume_local_state(
    data_dir: &Path,
    client: &reqwest::Client,
    controller: &Url,
    connection: &mut Connection,
    registration: &SyncRegistration,
    identity: &Identity,
) -> Result<()> {
    let sync_state = crate::load_sync_status(connection)?;
    let persisted_desired = verify_persisted_desired_state(
        connection,
        registration,
        sync_state.desired_revision_cursor,
    )?;
    if let Some(envelope) = persisted_desired.as_ref() {
        validate_and_report(
            data_dir,
            client,
            controller,
            connection,
            registration,
            identity,
            envelope,
        )
        .await?;
    }
    Ok(())
}

async fn validate_and_report(
    data_dir: &Path,
    client: &reqwest::Client,
    controller: &Url,
    connection: &mut Connection,
    registration: &SyncRegistration,
    identity: &Identity,
    envelope: &SignedDesiredState,
) -> Result<()> {
    let revision = envelope.document.revision;
    report_unreported_results(
        client,
        controller,
        connection,
        registration,
        identity,
        ReportScope::ReceivedFor(revision),
    )
    .await?;
    ensure_received_result_reported(connection, revision)?;
    crate::xray::validate_desired_state(data_dir, connection, envelope).await?;
    report_unreported_results(
        client,
        controller,
        connection,
        registration,
        identity,
        ReportScope::Revision(revision),
    )
    .await?;
    ensure_revision_results_reported(connection, revision)?;
    report_unreported_results(
        client,
        controller,
        connection,
        registration,
        identity,
        ReportScope::All,
    )
    .await
}

async fn send_heartbeat(
    client: &reqwest::Client,
    controller: &Url,
    connection: &Connection,
    registration: &SyncRegistration,
    identity: &Identity,
    desired_revision_cursor: i64,
    runtime_state: NodeRuntimeState,
) -> Result<()> {
    // Allocate before I/O. A failed attempt may leave a gap, but a generation
    // can never identify two different snapshots after a crash or retry.
    let heartbeat_generation = allocate_heartbeat_generation(connection)?;
    let heartbeat = current_heartbeat(
        connection,
        desired_revision_cursor,
        runtime_state,
        heartbeat_generation,
    )?;
    let heartbeat_body =
        serde_json::to_vec(&heartbeat).context("failed to serialize node heartbeat")?;
    let heartbeat_target = format!("/v1/nodes/{}/heartbeat", registration.node);
    let heartbeat_response = send_signed_request(
        client,
        controller,
        Method::POST,
        &heartbeat_target,
        heartbeat_body,
        registration,
        identity,
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
    persist_heartbeat_success(connection)
}

async fn fetch_and_process_desired(
    data_dir: &Path,
    client: &reqwest::Client,
    controller: &Url,
    connection: &mut Connection,
    registration: &SyncRegistration,
    identity: &Identity,
    desired_revision_cursor: i64,
) -> Result<()> {
    let desired_target = format!(
        "/v1/nodes/{}/desired?afterRevision={}",
        registration.node, desired_revision_cursor
    );
    let desired_response = send_signed_request(
        client,
        controller,
        Method::GET,
        &desired_target,
        Vec::new(),
        registration,
        identity,
    )
    .await
    .context("controller desired-state request failed")?;
    let desired_status = desired_response.status();
    let desired_is_json = response_is_json(&desired_response);
    let desired_body = read_bounded_response(desired_response).await?;
    match desired_status {
        StatusCode::NO_CONTENT if desired_body.is_empty() => {}
        StatusCode::NO_CONTENT => bail!("controller returned a body with no desired state"),
        StatusCode::OK if desired_is_json => {
            let envelope = persist_verified_desired_state(
                connection,
                registration,
                desired_revision_cursor,
                &desired_body,
            )?;
            validate_and_report(
                data_dir,
                client,
                controller,
                connection,
                registration,
                identity,
                &envelope,
            )
            .await?;
        }
        StatusCode::OK => bail!("controller desired-state response is not JSON"),
        status if !status.is_success() => {
            return Err(controller_error("desired-state", status, &desired_body));
        }
        _ => bail!("controller returned unexpected desired-state success status {desired_status}"),
    }
    Ok(())
}

fn current_heartbeat(
    connection: &Connection,
    desired_revision_cursor: i64,
    runtime_state: NodeRuntimeState,
    heartbeat_generation: SequenceNumber,
) -> Result<NodeHeartbeat> {
    let (received_revision_value, validated_revision_value): (i64, i64) = connection.query_row(
        "SELECT
            COALESCE(MAX(revision), 0),
            COALESCE(MAX(CASE
                WHEN state IN ('validated', 'applied') THEN revision
                ELSE NULL
            END), 0)
         FROM local_revision_results",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if received_revision_value != desired_revision_cursor {
        bail!("stored received revision does not match the desired-state cursor");
    }
    let desired_revision = optional_revision(desired_revision_cursor, "desired")?;
    let received_revision = optional_revision(received_revision_value, "received")?;
    let validated_revision = optional_revision(validated_revision_value, "validated")?;
    let applied_revision_value: i64 = connection.query_row(
        "SELECT COALESCE(applied_revision, 0)
         FROM xray_active_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let applied_revision = optional_revision(applied_revision_value, "applied")?;
    let endpoints = if runtime_state == NodeRuntimeState::Serving {
        crate::mapping::load_heartbeat_candidates(connection, applied_revision)?
    } else {
        Vec::new()
    };
    let heartbeat = NodeHeartbeat {
        heartbeat_generation,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        xray_version: crate::xray::configured_xray_version(connection)?,
        state: runtime_state,
        revisions: RevisionProgress {
            desired_revision,
            received_revision,
            validated_revision,
            applied_revision,
        },
        provider_paused: false,
        endpoints,
        telemetry_cursor: SequenceNumber::new(0).context("zero telemetry cursor must be valid")?,
    };
    heartbeat
        .validate()
        .context("generated node heartbeat is invalid")?;
    Ok(heartbeat)
}

fn allocate_heartbeat_generation(connection: &Connection) -> Result<SequenceNumber> {
    let updated = connection.execute(
        "UPDATE control_sync_state
         SET heartbeat_generation = heartbeat_generation + 1
         WHERE singleton = 1 AND heartbeat_generation < 9223372036854775807",
        [],
    )?;
    if updated != 1 {
        bail!("heartbeat generation is exhausted or sync state is missing");
    }
    let value: i64 = connection.query_row(
        "SELECT heartbeat_generation FROM control_sync_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    SequenceNumber::new(value).context("stored heartbeat generation is invalid")
}

fn optional_revision(value: i64, label: &str) -> Result<Option<Revision>> {
    if value == 0 {
        return Ok(None);
    }
    Revision::new(value)
        .with_context(|| format!("stored {label} revision is invalid"))
        .map(Some)
}

fn persist_verified_desired_state(
    connection: &mut Connection,
    registration: &SyncRegistration,
    previous_revision_cursor: i64,
    body: &[u8],
) -> Result<SignedDesiredState> {
    let envelope: SignedDesiredState =
        serde_json::from_slice(body).context("controller returned invalid desired-state JSON")?;
    let previous_revision = if previous_revision_cursor == 0 {
        None
    } else {
        Some(
            Revision::new(previous_revision_cursor)
                .context("stored desired revision cursor is invalid")?,
        )
    };
    envelope
        .validate_for(
            registration.network,
            registration.node,
            registration.controller_instance,
            previous_revision,
            SUPPORTED_DESIRED_SCHEMAS,
        )
        .context("controller desired-state document failed validation")?;
    verify_desired_state_signature(
        &envelope.document,
        &envelope.signature,
        &registration.controller_signing_public_key,
    )
    .context("controller desired-state signature is invalid")?;

    let canonical_envelope =
        serde_json::to_string(&envelope).context("failed to encode desired-state artifact")?;
    let transcript = desired_state_transcript(&envelope.document)
        .context("failed to encode desired-state transcript")?;
    let envelope_digest = sha256_digest(canonical_envelope.as_bytes());
    let transcript_digest = sha256_digest(&transcript);
    let now = unix_timestamp()?;
    let timestamp = Timestamp::from_datetime(OffsetDateTime::from_unix_timestamp(now)?);
    let result = RevisionResult {
        state: RevisionResultState::Received,
        config_digest: None,
        started_at: timestamp,
        completed_at: timestamp,
        error_code: None,
        rollback_revision: None,
    };
    result
        .validate(envelope.document.revision)
        .context("generated revision result is invalid")?;
    let report_json = serde_json::to_string(&result).context("failed to encode revision result")?;
    let report_digest = sha256_digest(report_json.as_bytes());

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let stored_cursor: i64 = transaction.query_row(
        "SELECT desired_revision_cursor FROM control_sync_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if stored_cursor != previous_revision_cursor {
        bail!("desired revision cursor changed during synchronization");
    }
    transaction.execute(
        "INSERT INTO desired_state_artifacts(
            revision, network_id, node_id, controller_instance_id, signing_key_id,
            envelope_json, envelope_digest, transcript_digest, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            envelope.document.revision.get(),
            envelope.document.network_id.to_string(),
            envelope.document.node_id.to_string(),
            envelope.document.controller_instance_id.to_string(),
            envelope.document.signing_key_id.to_string(),
            canonical_envelope,
            envelope_digest.as_str(),
            transcript_digest.as_str(),
            now,
        ],
    )?;
    transaction.execute(
        "INSERT INTO local_revision_results(
            revision, state, report_json, report_digest, reported_at, created_at
         ) VALUES (?1, 'received', ?2, ?3, NULL, ?4)",
        params![
            envelope.document.revision.get(),
            report_json,
            report_digest.as_str(),
            now,
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE control_sync_state SET desired_revision_cursor = ?1 WHERE singleton = 1",
        [envelope.document.revision.get()],
    )?;
    if updated != 1 {
        bail!("control sync state is missing");
    }
    transaction.commit()?;
    Ok(envelope)
}

fn verify_persisted_desired_state(
    connection: &Connection,
    registration: &SyncRegistration,
    desired_revision_cursor: i64,
) -> Result<Option<SignedDesiredState>> {
    let highest_artifact: i64 = connection.query_row(
        "SELECT COALESCE(MAX(revision), 0) FROM desired_state_artifacts",
        [],
        |row| row.get(0),
    )?;
    if highest_artifact != desired_revision_cursor {
        bail!("stored desired-state cursor does not match its immutable artifact");
    }
    if desired_revision_cursor == 0 {
        return Ok(None);
    }

    let stored = connection
        .query_row(
            "SELECT envelope_json, envelope_digest, transcript_digest
             FROM desired_state_artifacts WHERE revision = ?1",
            [desired_revision_cursor],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .context("stored desired-state artifact is missing")?;
    let envelope: SignedDesiredState =
        serde_json::from_str(&stored.0).context("stored desired-state artifact is invalid")?;
    if envelope.document.revision.get() != desired_revision_cursor {
        bail!("stored desired-state artifact revision is inconsistent");
    }
    envelope
        .validate_for(
            registration.network,
            registration.node,
            registration.controller_instance,
            None,
            SUPPORTED_DESIRED_SCHEMAS,
        )
        .context("stored desired-state document failed validation")?;
    verify_desired_state_signature(
        &envelope.document,
        &envelope.signature,
        &registration.controller_signing_public_key,
    )
    .context("stored desired-state signature is invalid")?;
    let transcript = desired_state_transcript(&envelope.document)
        .context("stored desired-state transcript is invalid")?;
    if sha256_digest(stored.0.as_bytes()).as_str() != stored.1
        || sha256_digest(&transcript).as_str() != stored.2
    {
        bail!("stored desired-state artifact digest is invalid");
    }
    Ok(Some(envelope))
}

async fn report_unreported_results(
    client: &reqwest::Client,
    controller: &Url,
    connection: &Connection,
    registration: &SyncRegistration,
    identity: &Identity,
    scope: ReportScope,
) -> Result<()> {
    let reports = load_unreported_results(connection, scope)?;

    for (revision_value, report_json, stored_digest) in reports {
        let revision =
            Revision::new(revision_value).context("stored revision result has invalid revision")?;
        let report: RevisionResult =
            serde_json::from_str(&report_json).context("stored revision result is invalid")?;
        report
            .validate(revision)
            .context("stored revision result failed validation")?;
        if sha256_digest(report_json.as_bytes()).as_str() != stored_digest {
            bail!("stored revision result digest is invalid");
        }

        let target = format!(
            "/v1/nodes/{}/revisions/{}/result",
            registration.node, revision_value
        );
        let response = send_signed_request(
            client,
            controller,
            Method::PUT,
            &target,
            report_json.into_bytes(),
            registration,
            identity,
        )
        .await
        .context("controller revision-result request failed")?;
        let status = response.status();
        let body = read_bounded_response(response).await?;
        if !status.is_success() {
            return Err(controller_error("revision-result", status, &body));
        }
        if status != StatusCode::NO_CONTENT || !body.is_empty() {
            bail!("controller returned unexpected revision-result success response");
        }
        let updated = connection.execute(
            "UPDATE local_revision_results SET reported_at = ?1
             WHERE revision = ?2 AND state = ?3 AND reported_at IS NULL",
            params![
                unix_timestamp()?,
                revision_value,
                revision_state_name(report.state)
            ],
        )?;
        if updated != 1 {
            bail!("stored revision result changed during synchronization");
        }
    }
    Ok(())
}

fn load_unreported_results(
    connection: &Connection,
    scope: ReportScope,
) -> Result<Vec<(i64, String, String)>> {
    let (target_revision, received_only) = match scope {
        ReportScope::ReceivedFor(revision) => (Some(revision.get()), 1_i64),
        ReportScope::Revision(revision) => (Some(revision.get()), 0_i64),
        ReportScope::All => (None, 0_i64),
    };
    let mut statement = connection.prepare(
        "SELECT revision, report_json, report_digest
         FROM local_revision_results
         WHERE reported_at IS NULL
           AND (?2 IS NULL OR revision = ?2)
           AND (?3 = 0 OR state = 'received')
         ORDER BY revision ASC,
             CASE state
                 WHEN 'received' THEN 10
                 WHEN 'validated' THEN 20
                 ELSE 30
             END ASC,
             state ASC
         LIMIT ?1",
    )?;
    let reports = statement
        .query_map(
            params![MAX_PENDING_REPORTS_PER_SYNC, target_revision, received_only],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(reports)
}

fn ensure_received_result_reported(connection: &Connection, revision: Revision) -> Result<()> {
    let reported_at = connection
        .query_row(
            "SELECT reported_at FROM local_revision_results
             WHERE revision = ?1 AND state = 'received'",
            [revision.get()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .context("desired-state revision is missing its received result")?;
    if reported_at.is_none() {
        bail!("current desired-state receipt has not been acknowledged by the controller");
    }
    Ok(())
}

fn ensure_revision_results_reported(connection: &Connection, revision: Revision) -> Result<()> {
    let pending: i64 = connection.query_row(
        "SELECT COUNT(*) FROM local_revision_results
         WHERE revision = ?1 AND reported_at IS NULL",
        [revision.get()],
        |row| row.get(0),
    )?;
    if pending != 0 {
        bail!("current desired-state results have not been acknowledged by the controller");
    }
    Ok(())
}

async fn send_signed_request(
    client: &reqwest::Client,
    controller: &Url,
    method: Method,
    path_and_query: &str,
    body: Vec<u8>,
    registration: &SyncRegistration,
    identity: &Identity,
) -> Result<reqwest::Response> {
    let method_name = method.as_str().to_owned();
    let has_json_body = matches!(method, Method::POST | Method::PUT);
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
    if has_json_body {
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

fn response_is_json(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn sha256_digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}

const fn revision_state_name(state: RevisionResultState) -> &'static str {
    match state {
        RevisionResultState::Received => "received",
        RevisionResultState::Validated => "validated",
        RevisionResultState::Applied => "applied",
        RevisionResultState::Rejected => "rejected",
        RevisionResultState::RolledBack => "rolledBack",
    }
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

#[cfg(test)]
mod tests {
    use super::{
        current_heartbeat, load_unreported_results, ReportScope, MAX_PENDING_REPORTS_PER_SYNC,
    };
    use control_protocol::id::{EndpointId, Revision, SequenceNumber};
    use control_protocol::node::NodeRuntimeState;
    use rusqlite::{params, Connection};

    #[test]
    fn current_revision_scope_bypasses_the_global_backlog_limit() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE local_revision_results (
                    revision INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    report_digest TEXT NOT NULL,
                    reported_at INTEGER
                ) STRICT;",
            )
            .unwrap();
        for revision in 1..=MAX_PENDING_REPORTS_PER_SYNC + 1 {
            connection
                .execute(
                    "INSERT INTO local_revision_results(
                        revision, state, report_json, report_digest, reported_at
                     ) VALUES (?1, 'received', ?2, 'digest', NULL)",
                    params![revision, format!("received-{revision}")],
                )
                .unwrap();
        }
        let current = Revision::new(MAX_PENDING_REPORTS_PER_SYNC + 1).unwrap();
        connection
            .execute(
                "INSERT INTO local_revision_results(
                    revision, state, report_json, report_digest, reported_at
                 ) VALUES (?1, 'validated', 'validated-current', 'digest', NULL)",
                [current.get()],
            )
            .unwrap();

        let received =
            load_unreported_results(&connection, ReportScope::ReceivedFor(current)).unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].0, current.get());
        assert_eq!(received[0].1, format!("received-{}", current.get()));

        let current_results =
            load_unreported_results(&connection, ReportScope::Revision(current)).unwrap();
        assert_eq!(current_results.len(), 2);
        assert_eq!(current_results[0].1, format!("received-{}", current.get()));
        assert_eq!(current_results[1].1, "validated-current");

        let global = load_unreported_results(&connection, ReportScope::All).unwrap();
        assert_eq!(
            global.len(),
            usize::try_from(MAX_PENDING_REPORTS_PER_SYNC).unwrap()
        );
        assert!(global.iter().all(|report| report.0 < current.get()));
    }

    #[test]
    fn heartbeat_reports_the_durable_applied_pointer_and_runtime_state() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE local_revision_results (
                    revision INTEGER NOT NULL,
                    state TEXT NOT NULL
                ) STRICT;
                 INSERT INTO local_revision_results(revision, state) VALUES
                    (1, 'received'), (1, 'validated'), (1, 'applied');
                 CREATE TABLE xray_active_state (
                    singleton INTEGER PRIMARY KEY,
                    applied_revision INTEGER
                 ) STRICT;
                 INSERT INTO xray_active_state(singleton, applied_revision) VALUES (1, 1);
                 CREATE TABLE provider_network_policy (
                    singleton INTEGER PRIMARY KEY,
                    automatic_router_mapping_enabled INTEGER NOT NULL,
                    router_mapping_consented_at INTEGER,
                    allow_permanent_upnp INTEGER NOT NULL
                 ) STRICT;
                 INSERT INTO provider_network_policy VALUES (1, 1, 1, 0);
                 CREATE TABLE router_mapping_leases (
                    endpoint_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    external_address TEXT NOT NULL,
                    external_port INTEGER NOT NULL,
                    applied_revision INTEGER NOT NULL,
                    lease_started_at INTEGER NOT NULL,
                    lease_expires_at INTEGER NOT NULL,
                    state TEXT NOT NULL
                 ) STRICT;",
            )
            .unwrap();
        let endpoint_id = EndpointId::new();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        connection
            .execute(
                "INSERT INTO router_mapping_leases(
                    endpoint_id, source, external_address, external_port,
                    applied_revision, lease_started_at, lease_expires_at, state
                 ) VALUES (?1, 'pcp', '8.8.8.8', 443, 1, ?2, ?3, 'active')",
                params![endpoint_id.to_string(), now, now + 3_600],
            )
            .unwrap();

        let heartbeat = current_heartbeat(
            &connection,
            1,
            NodeRuntimeState::Serving,
            SequenceNumber::new(7).unwrap(),
        )
        .unwrap();

        assert_eq!(heartbeat.state, NodeRuntimeState::Serving);
        assert_eq!(heartbeat.heartbeat_generation.get(), 7);
        assert_eq!(heartbeat.revisions.desired_revision.unwrap().get(), 1);
        assert_eq!(heartbeat.revisions.received_revision.unwrap().get(), 1);
        assert_eq!(heartbeat.revisions.validated_revision.unwrap().get(), 1);
        assert_eq!(heartbeat.revisions.applied_revision.unwrap().get(), 1);
        assert_eq!(heartbeat.endpoints.len(), 1);
        assert_eq!(heartbeat.endpoints[0].endpoint_id, endpoint_id);
        assert_eq!(heartbeat.endpoints[0].applied_revision.get(), 1);

        let idle = current_heartbeat(
            &connection,
            1,
            NodeRuntimeState::Idle,
            SequenceNumber::new(8).unwrap(),
        )
        .unwrap();
        assert!(idle.endpoints.is_empty());

        connection
            .execute(
                "UPDATE router_mapping_leases SET lease_expires_at = ?1",
                [now - 1],
            )
            .unwrap();
        let expired = current_heartbeat(
            &connection,
            1,
            NodeRuntimeState::Serving,
            SequenceNumber::new(9).unwrap(),
        )
        .unwrap();
        assert!(expired.endpoints.is_empty());
    }
}
