use crate::{migrate, open_database, unix_timestamp, DataDirLock};
use anyhow::{bail, Context, Result};
use control_protocol::crypto::Sha256Digest;
use control_protocol::id::{Count, NodeId, Revision, SequenceNumber, Timestamp, UserId};
use control_protocol::telemetry::{
    TelemetryBatch, TelemetryBatchAcknowledgement, TelemetryEvent, TelemetryEventKind,
    MAX_TELEMETRY_BATCH_BYTES, TELEMETRY_SCHEMA_VERSION,
};
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;
use xray_runtime::{
    query_user_traffic, ExecutionLimits, Sha256Digest as RuntimeSha256Digest, XrayBinarySpec,
};

const MAX_UNACKNOWLEDGED_EVENTS: i64 = 10_000;
const MAX_TOTAL_EVENTS: i64 = 100_000;
const MAX_SPOOL_BYTES: i64 = 64 * 1024 * 1024;
const MAX_UPLOAD_EVENTS: i64 = 512;
const ACKNOWLEDGED_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const STATS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const STATS_QUERY_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const STATUS_UNAVAILABLE: &str = "xray_stats_unavailable";
const STATUS_INVALID: &str = "xray_stats_invalid_output";
const STATUS_RESTARTED: &str = "xray_stats_restarted";
const STATUS_COUNTER_RESET: &str = "xray_stats_counter_reset";

#[derive(Clone, Debug)]
struct StatsQueryTarget {
    revision: Revision,
    runtime_generation: i64,
    binary_path: PathBuf,
    binary_digest: RuntimeSha256Digest,
    endpoint: SocketAddrV4,
    users_by_email: BTreeMap<String, UserId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CollectedUserCounter {
    email: String,
    uplink: i64,
    downlink: i64,
}

#[async_trait::async_trait]
trait StatsExecutor: Send + Sync {
    async fn query(&self, target: &StatsQueryTarget) -> Result<Vec<CollectedUserCounter>>;
}

struct XrayCliStatsExecutor;

#[async_trait::async_trait]
impl StatsExecutor for XrayCliStatsExecutor {
    async fn query(&self, target: &StatsQueryTarget) -> Result<Vec<CollectedUserCounter>> {
        let spec = XrayBinarySpec::new(target.binary_path.clone(), target.binary_digest)
            .context("stored Xray runtime path is invalid")?;
        let binary = tokio::task::spawn_blocking(move || spec.verify())
            .await
            .context("Xray Stats binary verification task failed")?
            .context("Xray Stats binary verification failed")?;
        let limits = ExecutionLimits::new(STATS_QUERY_TIMEOUT, STATS_QUERY_MAX_OUTPUT_BYTES)?;
        query_user_traffic(&binary, target.endpoint, limits)
            .await
            .context("bounded Xray Stats query failed")?
            .into_iter()
            .map(|counter| {
                Ok(CollectedUserCounter {
                    email: counter.email().as_str().to_string(),
                    uplink: counter.uplink(),
                    downlink: counter.downlink(),
                })
            })
            .collect()
    }
}

pub(crate) async fn collect_xray_traffic(data_dir: &Path) -> Result<()> {
    collect_xray_traffic_with(data_dir, &XrayCliStatsExecutor).await
}

async fn collect_xray_traffic_with<E>(data_dir: &Path, executor: &E) -> Result<()>
where
    E: StatsExecutor,
{
    let Some(target) = load_stats_query_target(data_dir)? else {
        return Ok(());
    };
    collect_target_with(data_dir, &target, executor).await
}

async fn collect_target_with<E>(
    data_dir: &Path,
    target: &StatsQueryTarget,
    executor: &E,
) -> Result<()>
where
    E: StatsExecutor,
{
    let counters = match executor.query(target).await {
        Ok(counters) => counters,
        Err(error) => {
            tracing::warn!(error = %error, "bounded Xray Stats collection failed");
            persist_collection_failure(data_dir, STATUS_UNAVAILABLE)?;
            return Ok(());
        }
    };
    let snapshot = match normalize_snapshot(target, counters) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(error = %error, "Xray Stats collection returned inconsistent users");
            persist_collection_failure(data_dir, STATUS_INVALID)?;
            return Ok(());
        }
    };
    apply_counter_snapshot(data_dir, target, &snapshot)
}

fn load_stats_query_target(data_dir: &Path) -> Result<Option<StatsQueryTarget>> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let (applied_revision, runtime_generation): (Option<i64>, i64) = connection.query_row(
        "SELECT applied_revision, generation FROM xray_active_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let Some(applied_revision) = applied_revision else {
        return Ok(None);
    };
    let revision = Revision::new(applied_revision).context("stored applied revision is invalid")?;
    if runtime_generation <= 0 {
        bail!("active Xray runtime generation is invalid");
    }
    let (binary_path, binary_digest, stats_api_port): (String, String, i64) = connection
        .query_row(
            "SELECT binary_path, expected_sha256, stats_api_port
         FROM xray_runtime_config WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let stats_api_port =
        u16::try_from(stats_api_port).context("stored Stats API port is invalid")?;
    if stats_api_port == 0 {
        bail!("stored Stats API port is invalid");
    }
    let envelope_json: String = connection.query_row(
        "SELECT envelope_json FROM desired_state_artifacts WHERE revision = ?1",
        [revision.get()],
        |row| row.get(0),
    )?;
    let envelope: control_protocol::node::SignedDesiredState =
        serde_json::from_str(&envelope_json).context("stored desired state is invalid")?;
    if envelope.document.revision != revision {
        bail!("stored desired state revision is inconsistent");
    }
    let users_by_email = envelope
        .document
        .users
        .iter()
        .filter(|user| user.enabled)
        .map(|user| (format!("user-{}", user.user_id), user.user_id))
        .collect();
    Ok(Some(StatsQueryTarget {
        revision,
        runtime_generation,
        binary_path: PathBuf::from(binary_path),
        binary_digest: RuntimeSha256Digest::from_hex(&binary_digest)
            .context("stored Xray checksum is invalid")?,
        endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, stats_api_port),
        users_by_email,
    }))
}

fn normalize_snapshot(
    target: &StatsQueryTarget,
    counters: Vec<CollectedUserCounter>,
) -> Result<BTreeMap<UserId, (i64, i64)>> {
    let mut snapshot = target
        .users_by_email
        .values()
        .copied()
        .map(|user_id| (user_id, (0, 0)))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeSet::new();
    for counter in counters {
        if counter.uplink < 0 || counter.downlink < 0 || !observed.insert(counter.email.clone()) {
            bail!("Xray Stats response contains invalid or duplicate counters");
        }
        let user_id = target
            .users_by_email
            .get(&counter.email)
            .context("Xray Stats response contains an unknown user")?;
        snapshot.insert(*user_id, (counter.uplink, counter.downlink));
    }
    Ok(snapshot)
}

fn persist_collection_failure(data_dir: &Path, code: &'static str) -> Result<()> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let now = unix_timestamp()?;
    let occurred_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    purge_acknowledged(&transaction, now)?;
    let previous: Option<String> = transaction.query_row(
        "SELECT last_status_code FROM xray_traffic_collection_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if previous.as_deref() == Some(code) {
        return transaction.commit().map_err(Into::into);
    }
    if let Some(previous) = previous {
        enqueue_in_transaction(
            &transaction,
            TelemetryEventKind::CollectionStatus {
                code: previous,
                recovered: true,
            },
            occurred_at,
            now,
        )?;
    }
    enqueue_in_transaction(
        &transaction,
        TelemetryEventKind::CollectionStatus {
            code: code.to_string(),
            recovered: false,
        },
        occurred_at,
        now,
    )?;
    transaction.execute(
        "UPDATE xray_traffic_collection_state SET last_status_code = ?1, updated_at = ?2
         WHERE singleton = 1",
        params![code, now],
    )?;
    transaction.commit()?;
    Ok(())
}

fn apply_counter_snapshot(
    data_dir: &Path,
    target: &StatsQueryTarget,
    snapshot: &BTreeMap<UserId, (i64, i64)>,
) -> Result<()> {
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let now = unix_timestamp()?;
    let occurred_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    purge_acknowledged(&transaction, now)?;
    let current_runtime: (Option<i64>, i64) = transaction.query_row(
        "SELECT applied_revision, generation FROM xray_active_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if current_runtime != (Some(target.revision.get()), target.runtime_generation) {
        bail!("Xray runtime changed while traffic counters were being collected");
    }
    let (previous_generation, previous_status): (Option<i64>, Option<String>) = transaction
        .query_row(
            "SELECT runtime_generation, last_status_code
             FROM xray_traffic_collection_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
    let previous_counters = load_previous_counters(&transaction)?;
    let generation_changed =
        previous_generation.is_some_and(|generation| generation != target.runtime_generation);
    let counter_reset = previous_generation == Some(target.runtime_generation)
        && snapshot.iter().any(|(user_id, (uplink, downlink))| {
            previous_counters
                .get(user_id)
                .is_some_and(|previous| *uplink < previous.0 || *downlink < previous.1)
        });
    let current_status = if generation_changed {
        Some(STATUS_RESTARTED)
    } else if counter_reset {
        Some(STATUS_COUNTER_RESET)
    } else {
        None
    };
    record_status_transition(
        &transaction,
        previous_status.as_deref(),
        current_status,
        occurred_at,
        now,
    )?;

    if previous_generation == Some(target.runtime_generation) {
        for (user_id, (uplink, downlink)) in snapshot {
            let Some(previous) = previous_counters.get(user_id) else {
                continue;
            };
            if *uplink < previous.0 || *downlink < previous.1 {
                continue;
            }
            let bytes_up = uplink - previous.0;
            let bytes_down = downlink - previous.1;
            if bytes_up == 0 && bytes_down == 0 {
                continue;
            }
            enqueue_in_transaction(
                &transaction,
                TelemetryEventKind::TrafficDelta {
                    user_id: *user_id,
                    bytes_up: Count::new(bytes_up)?,
                    bytes_down: Count::new(bytes_down)?,
                    // Xray's cumulative byte counters do not expose an exact
                    // new-connection count, so this collector does not infer one.
                    connection_count: Count::new(0)?,
                },
                occurred_at,
                now,
            )?;
        }
    }

    transaction.execute("DELETE FROM xray_user_traffic_counters", [])?;
    for (user_id, (uplink, downlink)) in snapshot {
        transaction.execute(
            "INSERT INTO xray_user_traffic_counters(
                user_id, runtime_generation, uplink_counter, downlink_counter, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                user_id.to_string(),
                target.runtime_generation,
                uplink,
                downlink,
                now
            ],
        )?;
    }
    transaction.execute(
        "UPDATE xray_traffic_collection_state
         SET runtime_generation = ?1, last_status_code = ?2, updated_at = ?3
         WHERE singleton = 1",
        params![target.runtime_generation, current_status, now],
    )?;
    transaction.commit()?;
    Ok(())
}

fn load_previous_counters(connection: &Connection) -> Result<BTreeMap<UserId, (i64, i64)>> {
    let mut statement = connection.prepare(
        "SELECT user_id, uplink_counter, downlink_counter
         FROM xray_user_traffic_counters ORDER BY user_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|row| {
            let (user_id, uplink, downlink) = row;
            Ok((
                user_id
                    .parse()
                    .context("stored traffic user ID is invalid")?,
                (uplink, downlink),
            ))
        })
        .collect()
}

fn record_status_transition(
    connection: &Connection,
    previous: Option<&str>,
    current: Option<&str>,
    occurred_at: Timestamp,
    now: i64,
) -> Result<()> {
    if previous == current {
        return Ok(());
    }
    if let Some(previous) = previous {
        enqueue_in_transaction(
            connection,
            TelemetryEventKind::CollectionStatus {
                code: previous.to_string(),
                recovered: true,
            },
            occurred_at,
            now,
        )?;
    }
    if let Some(current) = current {
        enqueue_in_transaction(
            connection,
            TelemetryEventKind::CollectionStatus {
                code: current.to_string(),
                recovered: false,
            },
            occurred_at,
            now,
        )?;
    }
    Ok(())
}

/// Persists one normalized event before it is eligible for upload.
///
/// # Errors
///
/// Returns an error if the host is unavailable, the event is invalid, sequence
/// space is exhausted, or the bounded durable spool is full.
pub fn record_telemetry_event(data_dir: &Path, kind: TelemetryEventKind) -> Result<SequenceNumber> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    enqueue(
        &mut connection,
        kind,
        Timestamp::from_datetime(OffsetDateTime::now_utc()),
    )
}

pub(crate) fn enqueue(
    connection: &mut Connection,
    kind: TelemetryEventKind,
    occurred_at: Timestamp,
) -> Result<SequenceNumber> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    purge_acknowledged(&transaction, now)?;
    let sequence = enqueue_in_transaction(&transaction, kind, occurred_at, now)?;
    transaction.commit()?;
    Ok(sequence)
}

fn enqueue_in_transaction(
    connection: &Connection,
    kind: TelemetryEventKind,
    occurred_at: Timestamp,
    now: i64,
) -> Result<SequenceNumber> {
    let (unacknowledged, total, bytes): (i64, i64, i64) = connection.query_row(
        "SELECT
            COUNT(*) FILTER (WHERE acknowledged_at IS NULL),
            COUNT(*),
            COALESCE(SUM(length(event_json)), 0)
         FROM telemetry_spool",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if unacknowledged >= MAX_UNACKNOWLEDGED_EVENTS
        || total >= MAX_TOTAL_EVENTS
        || bytes >= MAX_SPOOL_BYTES
    {
        bail!("bounded telemetry spool is full; no unacknowledged event was discarded");
    }
    let next_sequence: i64 = connection.query_row(
        "SELECT next_sequence FROM telemetry_spool_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let sequence = SequenceNumber::new(next_sequence).context("telemetry sequence is invalid")?;
    if sequence.get() == 0 {
        bail!("telemetry event sequence zero is reserved");
    }
    let event = TelemetryEvent {
        sequence,
        occurred_at,
        kind,
    };
    TelemetryBatch {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        node_id: NodeId::new(),
        first_sequence: sequence,
        last_sequence: sequence,
        events: vec![event.clone()],
    }
    .validate(&[TELEMETRY_SCHEMA_VERSION])
    .context("telemetry event failed protocol validation")?;
    let event_json = serde_json::to_string(&event)?;
    let digest = Sha256Digest::from_bytes(Sha256::digest(event_json.as_bytes()).into());
    let event_type = event_type(&event.kind);
    connection.execute(
        "INSERT INTO telemetry_spool(
            sequence, event_type, event_json, event_sha256,
            occurred_at, created_at, acknowledged_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
        params![
            sequence.get(),
            event_type,
            event_json,
            digest.as_str(),
            occurred_at.as_datetime().unix_timestamp(),
            now,
        ],
    )?;
    let next = next_sequence
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("telemetry sequence space is exhausted"))?;
    connection.execute(
        "UPDATE telemetry_spool_state SET next_sequence = ?1, updated_at = ?2
         WHERE singleton = 1 AND next_sequence = ?3",
        params![next, now, next_sequence],
    )?;
    Ok(sequence)
}

pub(crate) fn highest_sequence(connection: &Connection) -> Result<SequenceNumber> {
    let has_table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema
         WHERE type = 'table' AND name = 'telemetry_spool_state')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return SequenceNumber::new(0).context("zero telemetry sequence must be valid");
    }
    let next: i64 = connection.query_row(
        "SELECT next_sequence FROM telemetry_spool_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    SequenceNumber::new(next.saturating_sub(1)).context("stored telemetry sequence is invalid")
}

pub(crate) fn batch_from(
    connection: &Connection,
    node_id: NodeId,
    expected: SequenceNumber,
) -> Result<Option<TelemetryBatch>> {
    if expected.get() == 0 {
        bail!("controller telemetry cursor cannot expect sequence zero");
    }
    let next: i64 = connection.query_row(
        "SELECT next_sequence FROM telemetry_spool_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if expected.get() == next {
        return Ok(None);
    }
    if expected.get() > next {
        bail!("controller telemetry cursor is ahead of the local durable spool");
    }
    let first_retained: Option<i64> =
        connection.query_row("SELECT MIN(sequence) FROM telemetry_spool", [], |row| {
            row.get(0)
        })?;
    if first_retained.is_none_or(|first| expected.get() < first) {
        bail!("controller requests telemetry that is no longer retained locally");
    }
    let mut statement = connection.prepare(
        "SELECT sequence, event_json, event_sha256 FROM telemetry_spool
         WHERE sequence >= ?1 ORDER BY sequence LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![expected.get(), MAX_UPLOAD_EVENTS], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut events = Vec::with_capacity(rows.len());
    let mut bytes = 0_usize;
    for (sequence, event_json, digest) in rows {
        if Sha256Digest::from_bytes(Sha256::digest(event_json.as_bytes()).into()).as_str() != digest
        {
            bail!("stored telemetry event digest is invalid");
        }
        bytes = bytes
            .checked_add(event_json.len())
            .context("telemetry batch size overflow")?;
        if bytes > MAX_TELEMETRY_BATCH_BYTES / 2 && !events.is_empty() {
            break;
        }
        let event: TelemetryEvent =
            serde_json::from_str(&event_json).context("stored telemetry event is invalid")?;
        if event.sequence.get() != sequence {
            bail!("stored telemetry event sequence is inconsistent");
        }
        events.push(event);
    }
    let first_sequence = events
        .first()
        .map(|event| event.sequence)
        .context("retained telemetry range is unexpectedly empty")?;
    let last_sequence = events
        .last()
        .map(|event| event.sequence)
        .context("retained telemetry range is unexpectedly empty")?;
    let batch = TelemetryBatch {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        node_id,
        first_sequence,
        last_sequence,
        events,
    };
    batch
        .validate(&[TELEMETRY_SCHEMA_VERSION])
        .context("stored telemetry batch is not contiguous")?;
    Ok(Some(batch))
}

pub(crate) fn acknowledge(
    connection: &mut Connection,
    acknowledgement: TelemetryBatchAcknowledgement,
) -> Result<()> {
    acknowledgement
        .validate()
        .context("controller telemetry acknowledgement is invalid")?;
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (next, previous): (i64, i64) = transaction.query_row(
        "SELECT next_sequence, acknowledged_sequence
         FROM telemetry_spool_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let acknowledged = acknowledgement.acknowledged_sequence.get();
    if acknowledged >= next {
        bail!("controller acknowledged telemetry that was never persisted locally");
    }
    if acknowledged > previous {
        transaction.execute(
            "UPDATE telemetry_spool SET acknowledged_at = COALESCE(acknowledged_at, ?1)
             WHERE sequence <= ?2",
            params![now, acknowledged],
        )?;
        transaction.execute(
            "UPDATE telemetry_spool_state
             SET acknowledged_sequence = ?1, updated_at = ?2
             WHERE singleton = 1 AND acknowledged_sequence = ?3",
            params![acknowledged, now, previous],
        )?;
    }
    purge_acknowledged(&transaction, now)?;
    transaction.commit()?;
    Ok(())
}

fn purge_acknowledged(connection: &Connection, now: i64) -> Result<usize> {
    connection
        .execute(
            "DELETE FROM telemetry_spool
             WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ?1",
            [now.saturating_sub(ACKNOWLEDGED_RETENTION_SECONDS)],
        )
        .map_err(Into::into)
}

const fn event_type(kind: &TelemetryEventKind) -> &'static str {
    match kind {
        TelemetryEventKind::TrafficDelta { .. } => "trafficDelta",
        TelemetryEventKind::Connection { .. } => "connection",
        TelemetryEventKind::CollectionStatus { .. } => "collectionStatus",
        TelemetryEventKind::QuotaState { .. } => "quotaState",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        acknowledge, batch_from, collect_target_with, enqueue, highest_sequence,
        load_stats_query_target, CollectedUserCounter, StatsExecutor, StatsQueryTarget,
    };
    use crate::{migrate, open_database};
    use anyhow::{bail, Result};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use control_protocol::crypto::Ed25519Signature;
    use control_protocol::id::{
        ControllerInstanceId, Count, CredentialId, NetworkId, NodeId, Revision, SequenceNumber,
        SigningKeyId, Timestamp, UserId,
    };
    use control_protocol::node::{
        DesiredStateDocument, DesiredUser, DesiredXrayState, SignedDesiredState,
    };
    use control_protocol::secret::Secret;
    use control_protocol::telemetry::{
        TelemetryBatchAcknowledgement, TelemetryEvent, TelemetryEventKind,
    };
    use std::collections::{BTreeMap, VecDeque};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use time::OffsetDateTime;
    use xray_runtime::Sha256Digest as RuntimeSha256Digest;

    enum FakeResponse {
        Counters(Vec<CollectedUserCounter>),
        Failure,
    }

    struct FakeStatsExecutor {
        responses: Mutex<VecDeque<FakeResponse>>,
    }

    #[async_trait::async_trait]
    impl StatsExecutor for FakeStatsExecutor {
        async fn query(&self, _target: &StatsQueryTarget) -> Result<Vec<CollectedUserCounter>> {
            match self.responses.lock().unwrap().pop_front().unwrap() {
                FakeResponse::Counters(counters) => Ok(counters),
                FakeResponse::Failure => bail!("fake Stats API unavailable"),
            }
        }
    }

    #[test]
    fn spool_is_contiguous_replayable_and_acknowledged_only_after_commit() {
        let directory = tempfile::tempdir().unwrap();
        let mut connection = open_database(directory.path(), true).unwrap();
        migrate(&mut connection).unwrap();
        let user_id = UserId::new();
        for bytes in [7, 11] {
            enqueue(
                &mut connection,
                TelemetryEventKind::TrafficDelta {
                    user_id,
                    bytes_up: Count::new(bytes).unwrap(),
                    bytes_down: Count::new(1).unwrap(),
                    connection_count: Count::new(1).unwrap(),
                },
                Timestamp::from_datetime(OffsetDateTime::UNIX_EPOCH),
            )
            .unwrap();
        }
        assert_eq!(highest_sequence(&connection).unwrap().get(), 2);
        let batch = batch_from(&connection, NodeId::new(), SequenceNumber::new(1).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(batch.events.len(), 2);
        acknowledge(
            &mut connection,
            TelemetryBatchAcknowledgement {
                acknowledged_sequence: SequenceNumber::new(2).unwrap(),
                expected_sequence: SequenceNumber::new(3).unwrap(),
            },
        )
        .unwrap();
        let acknowledged: i64 = connection
            .query_row(
                "SELECT acknowledged_sequence FROM telemetry_spool_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(acknowledged, 2);
    }

    #[tokio::test]
    async fn cumulative_collection_is_restart_safe_and_never_infers_connections() {
        let directory = tempfile::tempdir().unwrap();
        let mut connection = open_database(directory.path(), true).unwrap();
        migrate(&mut connection).unwrap();
        install_active_revision(&connection, 1, "{}");
        drop(connection);

        let user_id = UserId::new();
        let email = format!("user-{user_id}");
        let mut users_by_email = BTreeMap::new();
        users_by_email.insert(email.clone(), user_id);
        let mut target = StatsQueryTarget {
            revision: Revision::new(1).unwrap(),
            runtime_generation: 1,
            binary_path: PathBuf::from("/explicit/fake-xray"),
            binary_digest: RuntimeSha256Digest::from_hex(&"00".repeat(32)).unwrap(),
            endpoint: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 31_337),
            users_by_email,
        };
        let executor = FakeStatsExecutor {
            responses: Mutex::new(VecDeque::from([
                counters(&email, 100, 200),
                counters(&email, 150, 260),
                counters(&email, 10, 20),
                counters(&email, 15, 25),
                counters(&email, 2, 3),
                counters(&email, 4, 5),
                FakeResponse::Failure,
                FakeResponse::Failure,
                counters(&email, 14, 15),
            ])),
        };

        collect_target_with(directory.path(), &target, &executor)
            .await
            .unwrap();
        assert!(events(directory.path()).is_empty());
        collect_target_with(directory.path(), &target, &executor)
            .await
            .unwrap();

        let connection = open_database(directory.path(), false).unwrap();
        connection
            .execute(
                "UPDATE xray_active_state SET generation = 2 WHERE singleton = 1",
                [],
            )
            .unwrap();
        drop(connection);
        target.runtime_generation = 2;
        for _ in 0..7 {
            collect_target_with(directory.path(), &target, &executor)
                .await
                .unwrap();
        }

        let events = events(directory.path());
        let traffic = events
            .iter()
            .filter_map(|event| match &event.kind {
                TelemetryEventKind::TrafficDelta {
                    bytes_up,
                    bytes_down,
                    connection_count,
                    ..
                } => Some((bytes_up.get(), bytes_down.get(), connection_count.get())),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(traffic, [(50, 60, 0), (5, 5, 0), (2, 2, 0), (10, 10, 0)]);

        let statuses = events
            .iter()
            .filter_map(|event| match &event.kind {
                TelemetryEventKind::CollectionStatus { code, recovered } => {
                    Some((code.as_str(), *recovered))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            [
                ("xray_stats_restarted", false),
                ("xray_stats_restarted", true),
                ("xray_stats_counter_reset", false),
                ("xray_stats_counter_reset", true),
                ("xray_stats_unavailable", false),
                ("xray_stats_unavailable", true),
            ]
        );
    }

    #[test]
    fn production_target_uses_applied_users_and_the_persisted_loopback_port() {
        let directory = tempfile::tempdir().unwrap();
        let mut connection = open_database(directory.path(), true).unwrap();
        migrate(&mut connection).unwrap();
        let user_id = UserId::new();
        let disabled_user_id = UserId::new();
        let envelope = SignedDesiredState {
            document: DesiredStateDocument {
                schema_version: 2,
                network_id: NetworkId::new(),
                node_id: NodeId::new(),
                revision: Revision::new(1).unwrap(),
                created_at: Timestamp::from_datetime(OffsetDateTime::UNIX_EPOCH),
                min_agent_version: "0.1.0".to_string(),
                users: vec![
                    DesiredUser {
                        user_id,
                        credential_id: CredentialId::new(),
                        vless_uuid: Secret::new("11111111-1111-4111-8111-111111111111".to_string()),
                        enabled: true,
                    },
                    DesiredUser {
                        user_id: disabled_user_id,
                        credential_id: CredentialId::new(),
                        vless_uuid: Secret::new("22222222-2222-4222-8222-222222222222".to_string()),
                        enabled: false,
                    },
                ],
                xray: DesiredXrayState {
                    listen_port: 20_443,
                    public_port: Some(443),
                    server_names: vec!["www.example.com".to_string()],
                    target: "www.example.com:443".to_string(),
                },
                signing_key_id: SigningKeyId::new(),
                controller_instance_id: ControllerInstanceId::new(),
            },
            signature: URL_SAFE_NO_PAD
                .encode([0_u8; 64])
                .parse::<Ed25519Signature>()
                .unwrap(),
        };
        install_active_revision(&connection, 7, &serde_json::to_string(&envelope).unwrap());
        connection
            .execute(
                "INSERT INTO xray_runtime_config(
                    singleton, binary_path, expected_sha256, version,
                    configured_at, updated_at, stats_api_port
                 ) VALUES (1, '/explicit/xray', ?1, 'Xray test', 0, 0, 31337)",
                ["0".repeat(64)],
            )
            .unwrap();
        drop(connection);

        let target = load_stats_query_target(directory.path()).unwrap().unwrap();
        assert_eq!(target.runtime_generation, 7);
        assert_eq!(target.endpoint.port(), 31_337);
        assert_eq!(target.users_by_email.len(), 1);
        assert_eq!(
            target.users_by_email.get(&format!("user-{user_id}")),
            Some(&user_id)
        );
        assert!(!target
            .users_by_email
            .contains_key(&format!("user-{disabled_user_id}")));
    }

    fn counters(email: &str, uplink: i64, downlink: i64) -> FakeResponse {
        FakeResponse::Counters(vec![CollectedUserCounter {
            email: email.to_string(),
            uplink,
            downlink,
        }])
    }

    fn install_active_revision(
        connection: &rusqlite::Connection,
        generation: i64,
        envelope_json: &str,
    ) {
        let digest = format!("sha256:{}", "0".repeat(64));
        connection
            .execute(
                "INSERT INTO desired_state_artifacts(
                    revision, network_id, node_id, controller_instance_id, signing_key_id,
                    envelope_json, envelope_digest, transcript_digest, received_at
                 ) VALUES (1, 'network', 'node', 'controller', 'key', ?1, ?2, ?2, 0)",
                rusqlite::params![envelope_json, digest],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO rendered_xray_configs(
                    revision, relative_path, config_digest, binary_digest, validated_at
                 ) VALUES (1, 'configs/1.json', ?1, ?2, 0)",
                rusqlite::params![digest, "0".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE xray_active_state
                 SET applied_revision = 1, config_digest = ?1, binary_digest = ?2,
                     generation = ?3, applied_at = 0, updated_at = 0
                 WHERE singleton = 1",
                rusqlite::params![digest, "0".repeat(64), generation],
            )
            .unwrap();
    }

    fn events(data_dir: &std::path::Path) -> Vec<TelemetryEvent> {
        let connection = open_database(data_dir, false).unwrap();
        let mut statement = connection
            .prepare("SELECT event_json FROM telemetry_spool ORDER BY sequence")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
            .collect()
    }
}
