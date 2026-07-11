use crate::{load_registration, unix_timestamp, SyncRegistration};
use anyhow::{bail, Context as _, Result};
use control_protocol::crypto::{ed25519_signing_key_id, Ed25519PublicKey, Sha256Digest};
use control_protocol::id::{ControllerInstanceId, NodeId, SequenceNumber};
use control_protocol::node::{NodeHeartbeatStatus, SignedNodeHeartbeatStatus};
use control_protocol::node_status::{
    node_heartbeat_status_transcript, verify_node_heartbeat_status_signature,
};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use sha2::{Digest as _, Sha256};

struct ControllerTrust {
    node_id: NodeId,
    controller_instance_id: ControllerInstanceId,
    signing_public_key: Ed25519PublicKey,
}

struct StoredControllerStatus {
    schema_version: i64,
    heartbeat_generation: i64,
    node_id: String,
    controller_instance_id: String,
    signing_key_id: String,
    observed_at: String,
    envelope_json: String,
    envelope_digest: String,
    transcript_digest: String,
}

pub(crate) fn persist_verified(
    connection: &mut Connection,
    registration: &SyncRegistration,
    heartbeat_generation: SequenceNumber,
    body: &[u8],
) -> Result<()> {
    let envelope: SignedNodeHeartbeatStatus = serde_json::from_slice(body)
        .context("controller returned invalid heartbeat-status JSON")?;
    let trust = ControllerTrust {
        node_id: registration.node,
        controller_instance_id: registration.controller_instance,
        signing_public_key: registration.controller_signing_public_key.clone(),
    };
    let transcript = verify_envelope(&trust, heartbeat_generation, &envelope)?;
    let envelope_json =
        serde_json::to_string(&envelope).context("failed to encode controller status artifact")?;
    let envelope_digest = sha256_digest(envelope_json.as_bytes());
    let transcript_digest = sha256_digest(&transcript);
    let now = unix_timestamp()?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous_generation = transaction
        .query_row(
            "SELECT heartbeat_generation FROM controller_status_state WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if previous_generation.is_some_and(|previous| previous > heartbeat_generation.get()) {
        bail!("controller heartbeat status generation regressed");
    }
    let updated = transaction.execute(
        "INSERT INTO controller_status_state(
            singleton, schema_version, heartbeat_generation, node_id,
            controller_instance_id, signing_key_id, observed_at, envelope_json,
            envelope_digest, transcript_digest, received_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(singleton) DO UPDATE SET
            schema_version = excluded.schema_version,
            heartbeat_generation = excluded.heartbeat_generation,
            node_id = excluded.node_id,
            controller_instance_id = excluded.controller_instance_id,
            signing_key_id = excluded.signing_key_id,
            observed_at = excluded.observed_at,
            envelope_json = excluded.envelope_json,
            envelope_digest = excluded.envelope_digest,
            transcript_digest = excluded.transcript_digest,
            received_at = excluded.received_at
         WHERE excluded.heartbeat_generation >= controller_status_state.heartbeat_generation",
        params![
            i64::from(envelope.document.schema_version),
            envelope.document.heartbeat_generation.get(),
            envelope.document.node_id.to_string(),
            envelope.document.controller_instance_id.to_string(),
            envelope.document.signing_key_id.to_string(),
            envelope.document.observed_at.to_string(),
            envelope_json,
            envelope_digest.as_str(),
            transcript_digest.as_str(),
            now,
        ],
    )?;
    if updated != 1 {
        bail!("controller heartbeat status changed during persistence");
    }
    let acknowledged = transaction.execute(
        "UPDATE control_sync_state SET last_heartbeat_at = ?1 WHERE singleton = 1",
        [now],
    )?;
    if acknowledged != 1 {
        bail!("control sync state is missing");
    }
    transaction.commit()?;
    Ok(())
}

pub(crate) fn load_verified(connection: &Connection) -> Result<Option<NodeHeartbeatStatus>> {
    let has_table: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = 'controller_status_state'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        let schema_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if schema_version >= 11 {
            bail!("verified controller status table is missing");
        }
        return Ok(None);
    }
    let stored = connection
        .query_row(
            "SELECT schema_version, heartbeat_generation, node_id,
                    controller_instance_id, signing_key_id, observed_at,
                    envelope_json, envelope_digest, transcript_digest
             FROM controller_status_state WHERE singleton = 1",
            [],
            |row| {
                Ok(StoredControllerStatus {
                    schema_version: row.get(0)?,
                    heartbeat_generation: row.get(1)?,
                    node_id: row.get(2)?,
                    controller_instance_id: row.get(3)?,
                    signing_key_id: row.get(4)?,
                    observed_at: row.get(5)?,
                    envelope_json: row.get(6)?,
                    envelope_digest: row.get(7)?,
                    transcript_digest: row.get(8)?,
                })
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let registration = load_registration(connection)?
        .context("stored controller status has no enrollment registration")?;
    let trust = ControllerTrust {
        node_id: registration
            .node_id
            .parse()
            .context("stored node ID is invalid")?,
        controller_instance_id: registration
            .controller_instance_id
            .parse()
            .context("stored controller instance ID is invalid")?,
        signing_public_key: registration
            .controller_signing_public_key
            .parse()
            .context("stored controller signing public key is invalid")?,
    };
    verify_stored(&trust, &stored).map(Some)
}

fn verify_stored(
    trust: &ControllerTrust,
    stored: &StoredControllerStatus,
) -> Result<NodeHeartbeatStatus> {
    if sha256_digest(stored.envelope_json.as_bytes()).as_str() != stored.envelope_digest {
        bail!("stored controller status artifact digest is invalid");
    }
    let envelope: SignedNodeHeartbeatStatus = serde_json::from_str(&stored.envelope_json)
        .context("stored controller status artifact is invalid")?;
    let canonical_envelope =
        serde_json::to_string(&envelope).context("stored controller status cannot be encoded")?;
    if canonical_envelope != stored.envelope_json {
        bail!("stored controller status artifact is not canonical");
    }
    let heartbeat_generation = SequenceNumber::new(stored.heartbeat_generation)
        .context("stored controller status generation is invalid")?;
    let transcript = verify_envelope(trust, heartbeat_generation, &envelope)
        .context("stored controller status failed verification")?;
    if stored.schema_version != i64::from(envelope.document.schema_version)
        || stored.node_id != envelope.document.node_id.to_string()
        || stored.controller_instance_id != envelope.document.controller_instance_id.to_string()
        || stored.signing_key_id != envelope.document.signing_key_id.to_string()
        || stored.observed_at != envelope.document.observed_at.to_string()
        || sha256_digest(&transcript).as_str() != stored.transcript_digest
    {
        bail!("stored controller status metadata is inconsistent");
    }
    Ok(envelope.document)
}

fn verify_envelope(
    trust: &ControllerTrust,
    heartbeat_generation: SequenceNumber,
    envelope: &SignedNodeHeartbeatStatus,
) -> Result<Vec<u8>> {
    envelope
        .document
        .validate_for(
            trust.node_id,
            heartbeat_generation,
            trust.controller_instance_id,
        )
        .context("controller heartbeat status document failed validation")?;
    let expected_signing_key_id = ed25519_signing_key_id(&trust.signing_public_key)
        .context("pinned controller signing public key is invalid")?;
    if envelope.document.signing_key_id != expected_signing_key_id {
        bail!("controller heartbeat status signing key identity is invalid");
    }
    verify_node_heartbeat_status_signature(
        &envelope.document,
        &envelope.signature,
        &trust.signing_public_key,
    )
    .context("controller heartbeat status signature is invalid")?;
    node_heartbeat_status_transcript(&envelope.document)
        .context("controller heartbeat status transcript is invalid")
}

fn sha256_digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(value).into())
}
