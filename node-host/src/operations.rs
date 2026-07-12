use crate::{migrate, open_database, parse_controller, DataDirLock};
use anyhow::{bail, Context, Result};
use control_protocol::id::NodeId;
use rusqlite::{Connection, OptionalExtension as _};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

/// Builds an allowlisted local support document with no key, credential,
/// endpoint address, rendered configuration, or raw child-process output.
///
/// # Errors
///
/// Returns an error when the locked local database is unavailable, corrupt, or unreadable.
pub fn support_bundle(data_dir: &Path) -> Result<serde_json::Value> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    build_support_bundle(&connection)
}

fn build_support_bundle(connection: &Connection) -> Result<serde_json::Value> {
    let controller: String = connection.query_row(
        "SELECT controller_url FROM host_config WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let controller = parse_controller(&controller)?;
    let registration: Option<(String, String)> = connection
        .query_row(
            "SELECT node_id, credential_expires_at
             FROM enrollment_registration WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let revisions: (i64, Option<i64>, i64) = connection.query_row(
        "SELECT
            (SELECT desired_revision_cursor FROM control_sync_state WHERE singleton = 1),
            (SELECT applied_revision FROM xray_active_state WHERE singleton = 1),
            (SELECT heartbeat_generation FROM control_sync_state WHERE singleton = 1)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let runtime: Option<(String, String)> = connection
        .query_row(
            "SELECT version, expected_sha256 FROM xray_runtime_config WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let spool: (i64, i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM telemetry_spool WHERE acknowledged_at IS NULL),
            (SELECT COUNT(*) FROM telemetry_spool WHERE acknowledged_at IS NOT NULL),
            (SELECT COALESCE(SUM(length(event_json)), 0) FROM telemetry_spool),
            (SELECT acknowledged_sequence FROM telemetry_spool_state WHERE singleton = 1)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    Ok(json!({
        "schemaVersion": 1,
        "nodeHost": {
            "databaseSchemaVersion": super::CURRENT_SCHEMA_VERSION,
            "controllerOrigin": controller.origin().ascii_serialization(),
            "nodeId": registration.as_ref().map(|value| &value.0),
            "credentialExpiresAt": registration.as_ref().map(|value| &value.1),
            "desiredRevision": revisions.0,
            "appliedRevision": revisions.1,
            "heartbeatGeneration": revisions.2,
            "xrayVersion": runtime.as_ref().map(|value| &value.0),
            "xrayExpectedSha256": runtime.as_ref().map(|value| &value.1),
        },
        "telemetrySpool": {
            "unacknowledgedEvents": spool.0,
            "retainedAcknowledgedEvents": spool.1,
            "serializedBytes": spool.2,
            "acknowledgedSequence": spool.3,
        }
    }))
}

/// Atomically detaches and removes local node state after exact identity
/// confirmation. Remote revocation remains a separate Control operation.
///
/// # Errors
///
/// Returns an error for a live owner, mismatched confirmation, unsafe path, or filesystem failure.
pub fn uninstall_local(data_dir: &Path, expected_node_id: NodeId) -> Result<()> {
    let lock = DataDirLock::acquire(data_dir, false)?;
    let mut connection = open_database(data_dir, false)?;
    migrate(&mut connection)?;
    let stored_node_id: String = connection
        .query_row(
            "SELECT node_id FROM enrollment_registration WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .context("node host is not enrolled")?;
    if stored_node_id != expected_node_id.to_string() {
        bail!("uninstall confirmation node ID does not match local enrollment");
    }
    let metadata = fs::symlink_metadata(data_dir)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("node data directory is unsafe");
    }
    let parent = data_dir
        .parent()
        .context("node data directory has no parent")?;
    let file_name = data_dir
        .file_name()
        .and_then(|value| value.to_str())
        .context("node data directory name is invalid")?;
    let tombstone = unique_tombstone(parent, file_name)?;
    drop(connection);
    fs::rename(data_dir, &tombstone).context("failed to atomically detach node data")?;
    sync_directory(parent)?;
    drop(lock);
    fs::remove_dir_all(&tombstone).context("failed to remove detached node data")?;
    sync_directory(parent)?;
    Ok(())
}

fn unique_tombstone(parent: &Path, file_name: &str) -> Result<PathBuf> {
    for _ in 0..32 {
        let candidate = parent.join(format!(".{file_name}.uninstall-{}", uuid::Uuid::new_v4()));
        if !candidate.try_exists()? {
            return Ok(candidate);
        }
    }
    bail!("could not allocate an uninstall tombstone path")
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_support_bundle;
    use crate::{initialize, migrate, open_database};

    #[test]
    fn support_bundle_is_allowlisted_and_contains_no_identity_material() {
        let directory = tempfile::tempdir().unwrap();
        initialize(directory.path(), "https://control.example").unwrap();
        let mut connection = open_database(directory.path(), false).unwrap();
        migrate(&mut connection).unwrap();
        let bundle = build_support_bundle(&connection).unwrap().to_string();
        assert!(!bundle.contains("privateKey"));
        assert!(!bundle.contains("vless"));
        assert!(!bundle.contains("reality"));
        assert!(!bundle.contains("identity.ed25519.seed"));
        assert!(bundle.contains("telemetrySpool"));
    }
}
