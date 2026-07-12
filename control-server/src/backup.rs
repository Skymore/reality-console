//! Offline-safe controller backup verification and atomic recovery operations.

use crate::db::{
    migration_set_sha256, verify_current_migration_history, APPLICATION_ID, SCHEMA_VERSION,
};
use crate::identity::{identity_path, set_owner_only, ControllerIdentity, IdentityError};
use control_protocol::crypto::ed25519_signing_key_id;
use fs2::FileExt as _;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::{Builder, TempDir};
use thiserror::Error;

const BACKUP_SCHEMA_VERSION: u16 = 1;
const DATABASE_FILE: &str = "control.sqlite3";
const IDENTITY_FILE: &str = "control.sqlite3.controller-ed25519";
const MANIFEST_FILE: &str = "manifest.json";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"private-network/control-backup-manifest/v1\0";

/// Explicit declaration that the destination encrypts the complete backup artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalEncryptionContract(String);

impl ExternalEncryptionContract {
    /// Creates a non-secret identifier for an operator-managed encrypted destination.
    ///
    /// The controller does not encrypt its identity sidecar. Supplying this value is an
    /// acknowledgement that the destination encrypts the entire backup directory at rest.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InvalidEncryptionContract`] for unsafe or unbounded labels.
    pub fn new(value: impl Into<String>) -> Result<Self, BackupError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(BackupError::InvalidEncryptionContract);
        }
        Ok(Self(value))
    }
}

/// Inputs for one consistent controller backup.
#[derive(Clone, Debug)]
pub struct CreateBackupOptions {
    pub source_database: PathBuf,
    pub destination: PathBuf,
    pub external_encryption: ExternalEncryptionContract,
}

/// A baseline that makes rollback detection explicit during recovery.
#[derive(Clone, Debug)]
pub enum RestoreBaseline {
    /// Compare the candidate against this stopped controller database.
    CurrentDatabase(PathBuf),
    /// No controller state has ever existed at this recovery destination.
    NoLocalHistory,
}

/// A deliberate capability required by every restore, including dry runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMode {
    Explicit,
}

/// Inputs for verification and atomic recovery into a new generation directory.
#[derive(Clone, Debug)]
pub struct RestoreOptions {
    pub backup: PathBuf,
    pub destination: PathBuf,
    pub baseline: RestoreBaseline,
    pub recovery_mode: RecoveryMode,
    pub dry_run: bool,
}

/// Non-secret operator output for backup and recovery commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupReport {
    pub backup_schema_version: u16,
    pub database_schema_version: i64,
    pub network_id: String,
    pub controller_instance_id: String,
    pub controller_fingerprint: String,
    pub database_sha256: String,
    pub manifest_sha256: String,
    pub external_encryption_contract: String,
}

/// Non-secret result of a restore or restore dry run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub verified: bool,
    pub restored: bool,
    pub dry_run: bool,
    pub network_id: String,
    pub controller_instance_id: String,
    pub controller_fingerprint: String,
    pub database_schema_version: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupManifest {
    payload: BackupManifestPayload,
    manifest_sha256: String,
    manifest_signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupManifestPayload {
    backup_schema_version: u16,
    created_at_unix: u64,
    database_file: String,
    identity_file: String,
    database_sha256: String,
    identity_sha256: String,
    application_id: i64,
    database_schema_version: i64,
    migration_set_sha256: String,
    network_id: String,
    controller_instance_id: String,
    controller_signing_public_key: String,
    controller_signing_key_id: String,
    controller_fingerprint: String,
    high_water: HighWaterMarks,
    protection: BackupProtection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupProtection {
    kind: String,
    external_encryption_contract: String,
    controller_encrypted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HighWaterMarks {
    network_revision: i64,
    audit_event_id: i64,
    sqlite_sequences: BTreeMap<String, i64>,
    node_telemetry_sequences: BTreeMap<String, i64>,
    session_generations: BTreeMap<String, i64>,
    device_bundle_generations: BTreeMap<String, i64>,
    node_canary_generations: BTreeMap<String, i64>,
}

struct InspectedController {
    network_id: String,
    controller_instance_id: String,
    controller_signing_public_key: String,
    controller_signing_key_id: String,
    controller_fingerprint: String,
    high_water: HighWaterMarks,
}

/// Creates an online-consistent `SQLite` snapshot in a new encrypted destination directory.
///
/// # Errors
///
/// The operation fails closed on an existing destination, unsafe identity file, invalid or old
/// schema, failed integrity checks, identity mismatch, or any staging/persistence failure.
pub fn create_backup(options: &CreateBackupOptions) -> Result<BackupReport, BackupError> {
    let parent = destination_parent(&options.destination)?;
    let _operation_lock = OperationLock::acquire(parent)?;
    ensure_destination_absent(&options.destination)?;
    let staging = owner_only_staging(parent, ".control-backup-stage-")?;
    let staging_database = staging.path().join(DATABASE_FILE);
    let staging_identity = staging.path().join(IDENTITY_FILE);

    create_sqlite_snapshot(&options.source_database, &staging_database)?;
    copy_regular_owner_only(&identity_path(&options.source_database), &staging_identity)?;
    let inspected = inspect_controller(&staging_database, &staging_identity)?;
    let payload = BackupManifestPayload {
        backup_schema_version: BACKUP_SCHEMA_VERSION,
        created_at_unix: unix_timestamp()?,
        database_file: DATABASE_FILE.to_string(),
        identity_file: IDENTITY_FILE.to_string(),
        database_sha256: sha256_file(&staging_database)?,
        identity_sha256: sha256_file(&staging_identity)?,
        application_id: APPLICATION_ID,
        database_schema_version: SCHEMA_VERSION,
        migration_set_sha256: migration_set_sha256(),
        network_id: inspected.network_id,
        controller_instance_id: inspected.controller_instance_id,
        controller_signing_public_key: inspected.controller_signing_public_key,
        controller_signing_key_id: inspected.controller_signing_key_id,
        controller_fingerprint: inspected.controller_fingerprint,
        high_water: inspected.high_water,
        protection: BackupProtection {
            kind: "externalEncryptedDestination".to_string(),
            external_encryption_contract: options.external_encryption.0.clone(),
            controller_encrypted: false,
        },
    };
    let identity = ControllerIdentity::load_existing(&staging_identity)?;
    let manifest = seal_manifest(payload, &identity)?;
    write_owner_only_json(&staging.path().join(MANIFEST_FILE), &manifest)?;
    sync_directory(staging.path())?;
    let report = verify_backup(staging.path())?;
    persist_staging(staging, &options.destination)?;
    sync_directory(parent)?;
    Ok(report)
}

/// Fully verifies a backup without exposing its identity material.
///
/// # Errors
///
/// Returns an error for unsafe layouts, digest mismatch, unsupported schema, corruption,
/// migration mismatch, foreign-key violation, or controller identity mismatch.
pub fn verify_backup(backup: &Path) -> Result<BackupReport, BackupError> {
    ensure_exact_backup_layout(backup)?;
    let manifest = read_manifest(&backup.join(MANIFEST_FILE))?;
    verify_manifest_digest(&manifest)?;
    validate_manifest_contract(&manifest.payload)?;
    let database = backup.join(DATABASE_FILE);
    let identity = backup.join(IDENTITY_FILE);
    ensure_digest(&database, &manifest.payload.database_sha256, "database")?;
    ensure_digest(&identity, &manifest.payload.identity_sha256, "identity")?;
    let inspected = inspect_controller(&database, &identity)?;
    ensure_manifest_matches_controller(&manifest.payload, &inspected)?;
    verify_manifest_signature(&manifest, &identity)?;
    Ok(report_from_manifest(&manifest))
}

/// Verifies and atomically restores a backup into a previously absent generation directory.
///
/// The caller must then explicitly switch its service configuration to the returned generation.
/// Existing directories are never replaced. A current baseline is exclusively locked while its
/// high-water marks are compared, preventing restore while the service is still running.
///
/// # Errors
///
/// Returns an error for rollback, identity mismatch, a running controller, an existing
/// destination, invalid artifacts, or any staging/persistence failure.
pub fn restore_backup(options: &RestoreOptions) -> Result<RestoreReport, BackupError> {
    restore_backup_with_hook(options, || Ok(()))
}

fn restore_backup_with_hook(
    options: &RestoreOptions,
    before_persist: impl FnOnce() -> Result<(), BackupError>,
) -> Result<RestoreReport, BackupError> {
    let RecoveryMode::Explicit = options.recovery_mode;
    let verified = verify_backup(&options.backup)?;
    let manifest = read_manifest(&options.backup.join(MANIFEST_FILE))?;
    let _baseline_lock;
    if let RestoreBaseline::CurrentDatabase(current_database) = &options.baseline {
        _baseline_lock = Some(OperationLock::acquire_database(current_database)?);
        let current_identity = identity_path(current_database);
        let current = inspect_controller(current_database, &current_identity)?;
        ensure_same_controller(&manifest.payload, &current)?;
        ensure_not_rollback(&manifest.payload.high_water, &current.high_water)?;
    } else {
        _baseline_lock = None;
    }

    if options.dry_run {
        return Ok(RestoreReport {
            verified: true,
            restored: false,
            dry_run: true,
            network_id: verified.network_id,
            controller_instance_id: verified.controller_instance_id,
            controller_fingerprint: verified.controller_fingerprint,
            database_schema_version: verified.database_schema_version,
        });
    }

    let parent = destination_parent(&options.destination)?;
    let _operation_lock = OperationLock::acquire(parent)?;
    ensure_destination_absent(&options.destination)?;
    let staging = owner_only_staging(parent, ".control-restore-stage-")?;
    for name in [DATABASE_FILE, IDENTITY_FILE, MANIFEST_FILE] {
        copy_regular_owner_only(&options.backup.join(name), &staging.path().join(name))?;
    }
    sync_directory(staging.path())?;
    verify_backup(staging.path())?;
    before_persist()?;
    persist_staging(staging, &options.destination)?;
    sync_directory(parent)?;
    Ok(RestoreReport {
        verified: true,
        restored: true,
        dry_run: false,
        network_id: verified.network_id,
        controller_instance_id: verified.controller_instance_id,
        controller_fingerprint: verified.controller_fingerprint,
        database_schema_version: verified.database_schema_version,
    })
}

fn create_sqlite_snapshot(source_path: &Path, destination_path: &Path) -> Result<(), BackupError> {
    ensure_regular_file(source_path, "database")?;
    let source = open_read_only(source_path)?;
    let mut destination = Connection::open(destination_path)?;
    let backup = Backup::new(&source, &mut destination)?;
    backup.run_to_completion(64, Duration::from_millis(25), None)?;
    drop(backup);
    let journal_mode: String =
        destination.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if journal_mode != "delete" {
        return Err(BackupError::SnapshotFinalizationFailed);
    }
    destination.close().map_err(|(_, error)| error)?;
    set_owner_only(destination_path)?;
    File::open(destination_path)?.sync_all()?;
    Ok(())
}

fn inspect_controller(
    database_path: &Path,
    identity_file: &Path,
) -> Result<InspectedController, BackupError> {
    ensure_regular_file(database_path, "database")?;
    ensure_regular_file(identity_file, "identity")?;
    let connection = open_read_only(database_path)?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(BackupError::WrongApplicationId);
    }
    verify_current_migration_history(&connection)?;
    verify_integrity(&connection)?;
    let (network_id, controller_instance_id, network_revision): (String, String, i64) = connection
        .query_row(
            "SELECT network_id, controller_epoch, last_revision FROM networks",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let identity = ControllerIdentity::load_existing(identity_file)?;
    let public_key = identity.public_key();
    let signing_key_id =
        ed25519_signing_key_id(&public_key).map_err(|_| BackupError::ControllerIdentityMismatch)?;
    let public_key = public_key.as_str().to_owned();
    let fingerprint = identity.fingerprint().as_str().to_owned();
    verify_stored_controller_bindings(
        &connection,
        &controller_instance_id,
        &public_key,
        &signing_key_id.to_string(),
    )?;
    Ok(InspectedController {
        network_id,
        controller_instance_id,
        controller_signing_public_key: public_key,
        controller_signing_key_id: signing_key_id.to_string(),
        controller_fingerprint: fingerprint,
        high_water: load_high_water(&connection, network_revision)?,
    })
}

fn open_read_only(path: &Path) -> Result<Connection, BackupError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.execute_batch(
        "PRAGMA query_only = ON;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA busy_timeout = 5000;",
    )?;
    Ok(connection)
}

fn verify_integrity(connection: &Connection) -> Result<(), BackupError> {
    let mut statement = connection.prepare("PRAGMA integrity_check")?;
    let messages = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if messages.as_slice() != ["ok"] {
        return Err(BackupError::IntegrityCheckFailed);
    }
    if connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(BackupError::ForeignKeyViolation);
    }
    Ok(())
}

fn verify_stored_controller_bindings(
    connection: &Connection,
    controller_instance_id: &str,
    signing_public_key: &str,
    signing_key_id: &str,
) -> Result<(), BackupError> {
    let bad_revision: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM config_revisions
            WHERE controller_instance_id <> ?1 OR signing_key_id <> ?2
        )",
        (controller_instance_id, signing_key_id),
        |row| row.get(0),
    )?;
    let bad_activation: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM device_activations
            WHERE controller_instance_id <> ?1 OR bundle_signing_public_key <> ?2
        )",
        (controller_instance_id, signing_public_key),
        |row| row.get(0),
    )?;
    if bad_revision || bad_activation {
        return Err(BackupError::StoredControllerBindingMismatch);
    }
    Ok(())
}

fn load_high_water(
    connection: &Connection,
    network_revision: i64,
) -> Result<HighWaterMarks, BackupError> {
    Ok(HighWaterMarks {
        network_revision,
        audit_event_id: connection.query_row(
            "SELECT COALESCE(MAX(event_id), 0) FROM audit_events",
            [],
            |row| row.get(0),
        )?,
        sqlite_sequences: load_keyed_marks(
            connection,
            "SELECT name, seq FROM sqlite_sequence ORDER BY name",
        )?,
        node_telemetry_sequences: load_keyed_marks(
            connection,
            "SELECT node_id, acknowledged_sequence FROM node_telemetry_cursors ORDER BY node_id",
        )?,
        session_generations: load_keyed_marks(
            connection,
            "SELECT session_id, generation FROM refresh_sessions ORDER BY session_id",
        )?,
        device_bundle_generations: load_keyed_marks(
            connection,
            "SELECT device_id, MAX(generation) FROM profile_bundles GROUP BY device_id ORDER BY device_id",
        )?,
        node_canary_generations: load_keyed_marks(
            connection,
            "SELECT node_id, MAX(generation) FROM endpoint_canary_credentials GROUP BY node_id ORDER BY node_id",
        )?,
    })
}

fn load_keyed_marks(
    connection: &Connection,
    sql: &str,
) -> Result<BTreeMap<String, i64>, BackupError> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let mut values = BTreeMap::new();
    for row in rows {
        let (key, value) = row?;
        values.insert(key, value);
    }
    Ok(values)
}

fn ensure_not_rollback(
    candidate: &HighWaterMarks,
    baseline: &HighWaterMarks,
) -> Result<(), BackupError> {
    if candidate.network_revision < baseline.network_revision
        || candidate.audit_event_id < baseline.audit_event_id
    {
        return Err(BackupError::HighWaterRollback);
    }
    for (candidate_map, baseline_map) in [
        (&candidate.sqlite_sequences, &baseline.sqlite_sequences),
        (
            &candidate.node_telemetry_sequences,
            &baseline.node_telemetry_sequences,
        ),
        (
            &candidate.session_generations,
            &baseline.session_generations,
        ),
        (
            &candidate.device_bundle_generations,
            &baseline.device_bundle_generations,
        ),
        (
            &candidate.node_canary_generations,
            &baseline.node_canary_generations,
        ),
    ] {
        if baseline_map
            .iter()
            .any(|(key, value)| candidate_map.get(key).copied().unwrap_or_default() < *value)
        {
            return Err(BackupError::HighWaterRollback);
        }
    }
    Ok(())
}

fn seal_manifest(
    payload: BackupManifestPayload,
    identity: &ControllerIdentity,
) -> Result<BackupManifest, BackupError> {
    let payload_bytes = serde_json::to_vec(&payload)?;
    let manifest_sha256 = sha256_bytes(&payload_bytes);
    let manifest_signature = identity
        .sign(&manifest_signature_transcript(&payload_bytes))?
        .as_str()
        .to_owned();
    Ok(BackupManifest {
        payload,
        manifest_sha256,
        manifest_signature,
    })
}

fn verify_manifest_digest(manifest: &BackupManifest) -> Result<(), BackupError> {
    let actual = sha256_bytes(&serde_json::to_vec(&manifest.payload)?);
    if actual != manifest.manifest_sha256 {
        return Err(BackupError::ManifestDigestMismatch);
    }
    Ok(())
}

fn verify_manifest_signature(
    manifest: &BackupManifest,
    identity_file: &Path,
) -> Result<(), BackupError> {
    let identity = ControllerIdentity::load_existing(identity_file)?;
    let payload_bytes = serde_json::to_vec(&manifest.payload)?;
    let expected = identity.sign(&manifest_signature_transcript(&payload_bytes))?;
    if expected.as_str() != manifest.manifest_signature {
        return Err(BackupError::ManifestSignatureMismatch);
    }
    Ok(())
}

fn manifest_signature_transcript(payload: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + payload.len());
    transcript.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(payload);
    transcript
}

fn validate_manifest_contract(payload: &BackupManifestPayload) -> Result<(), BackupError> {
    if payload.backup_schema_version != BACKUP_SCHEMA_VERSION
        || payload.database_file != DATABASE_FILE
        || payload.identity_file != IDENTITY_FILE
        || payload.application_id != APPLICATION_ID
        || payload.database_schema_version != SCHEMA_VERSION
        || payload.migration_set_sha256 != migration_set_sha256()
    {
        return Err(BackupError::UnsupportedManifest);
    }
    if payload.protection.kind != "externalEncryptedDestination"
        || payload.protection.controller_encrypted
        || ExternalEncryptionContract::new(payload.protection.external_encryption_contract.clone())
            .is_err()
    {
        return Err(BackupError::InvalidEncryptionContract);
    }
    Ok(())
}

fn ensure_manifest_matches_controller(
    payload: &BackupManifestPayload,
    inspected: &InspectedController,
) -> Result<(), BackupError> {
    if payload.network_id != inspected.network_id
        || payload.controller_instance_id != inspected.controller_instance_id
        || payload.controller_signing_public_key != inspected.controller_signing_public_key
        || payload.controller_signing_key_id != inspected.controller_signing_key_id
        || payload.controller_fingerprint != inspected.controller_fingerprint
    {
        return Err(BackupError::ControllerIdentityMismatch);
    }
    if payload.high_water != inspected.high_water {
        return Err(BackupError::HighWaterMismatch);
    }
    Ok(())
}

fn ensure_same_controller(
    candidate: &BackupManifestPayload,
    current: &InspectedController,
) -> Result<(), BackupError> {
    if candidate.network_id != current.network_id
        || candidate.controller_instance_id != current.controller_instance_id
        || candidate.controller_signing_public_key != current.controller_signing_public_key
        || candidate.controller_signing_key_id != current.controller_signing_key_id
        || candidate.controller_fingerprint != current.controller_fingerprint
    {
        return Err(BackupError::RecoveryBaselineMismatch);
    }
    Ok(())
}

fn report_from_manifest(manifest: &BackupManifest) -> BackupReport {
    BackupReport {
        backup_schema_version: manifest.payload.backup_schema_version,
        database_schema_version: manifest.payload.database_schema_version,
        network_id: manifest.payload.network_id.clone(),
        controller_instance_id: manifest.payload.controller_instance_id.clone(),
        controller_fingerprint: manifest.payload.controller_fingerprint.clone(),
        database_sha256: manifest.payload.database_sha256.clone(),
        manifest_sha256: manifest.manifest_sha256.clone(),
        external_encryption_contract: manifest
            .payload
            .protection
            .external_encryption_contract
            .clone(),
    }
}

fn read_manifest(path: &Path) -> Result<BackupManifest, BackupError> {
    ensure_regular_file(path, "manifest")?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(BackupError::ManifestTooLarge);
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn ensure_exact_backup_layout(directory: &Path) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BackupError::UnsafeArtifactLayout);
    }
    let mut names = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    let mut expected = vec![
        DATABASE_FILE.to_string(),
        IDENTITY_FILE.to_string(),
        MANIFEST_FILE.to_string(),
    ];
    expected.sort();
    if names != expected {
        return Err(BackupError::UnsafeArtifactLayout);
    }
    for name in [DATABASE_FILE, IDENTITY_FILE, MANIFEST_FILE] {
        ensure_regular_file(&directory.join(name), name)?;
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, _kind: &'static str) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::UnsafeArtifactLayout);
    }
    Ok(())
}

fn ensure_digest(path: &Path, expected: &str, kind: &'static str) -> Result<(), BackupError> {
    if sha256_file(path)? != expected {
        return Err(BackupError::ArtifactDigestMismatch(kind));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, BackupError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn write_owner_only_json(path: &Path, value: &impl Serialize) -> Result<(), BackupError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = owner_only_open_options()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    set_owner_only(path)?;
    Ok(())
}

fn copy_regular_owner_only(source: &Path, destination: &Path) -> Result<(), BackupError> {
    ensure_regular_file(source, "source")?;
    let mut input = File::open(source)?;
    let mut output = owner_only_open_options()
        .create_new(true)
        .write(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    set_owner_only(destination)?;
    Ok(())
}

fn owner_only_staging(parent: &Path, prefix: &str) -> Result<TempDir, BackupError> {
    let staging = Builder::new().prefix(prefix).tempdir_in(parent)?;
    set_directory_owner_only(staging.path())?;
    Ok(staging)
}

fn persist_staging(staging: TempDir, destination: &Path) -> Result<(), BackupError> {
    ensure_destination_absent(destination)?;
    let staging_path = staging.keep();
    match fs::rename(&staging_path, destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_dir_all(&staging_path);
            Err(error.into())
        }
    }
}

fn destination_parent(destination: &Path) -> Result<&Path, BackupError> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(parent)
}

fn ensure_destination_absent(destination: &Path) -> Result<(), BackupError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(BackupError::DestinationExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn unix_timestamp() -> Result<u64, BackupError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BackupError::Clock)?
        .as_secs())
}

fn sync_directory(path: &Path) -> Result<(), BackupError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn owner_only_open_options() -> OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.mode(0o600);
    options
}

#[cfg(not(unix))]
fn owner_only_open_options() -> OpenOptions {
    OpenOptions::new()
}

#[cfg(unix)]
fn set_directory_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_directory_owner_only(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

struct OperationLock {
    file: File,
}

impl OperationLock {
    fn acquire(parent: &Path) -> Result<Self, BackupError> {
        Self::acquire_path(&parent.join(".control-operations.lock"))
    }

    fn acquire_database(database: &Path) -> Result<Self, BackupError> {
        let mut name = database.as_os_str().to_os_string();
        name.push(".lock");
        Self::acquire_path(Path::new(&name))
    }

    fn acquire_path(path: &Path) -> Result<Self, BackupError> {
        let file = owner_only_open_options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        set_owner_only(path)?;
        file.try_lock_exclusive()
            .map_err(|_| BackupError::ControllerStillRunning)?;
        Ok(Self { file })
    }
}

impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Fail-closed errors intended for redacted operator display.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("the external encryption contract must be a non-secret identifier using 1-128 safe characters")]
    InvalidEncryptionContract,
    #[error("the destination already exists; recovery never overwrites an existing directory")]
    DestinationExists,
    #[error("the backup artifact layout contains missing, extra, non-regular, or linked entries")]
    UnsafeArtifactLayout,
    #[error("the backup manifest exceeds the size limit")]
    ManifestTooLarge,
    #[error("the backup manifest schema or migration set is unsupported")]
    UnsupportedManifest,
    #[error("the backup manifest digest does not match its payload")]
    ManifestDigestMismatch,
    #[error("the backup manifest signature does not match the controller signing identity")]
    ManifestSignatureMismatch,
    #[error("the {0} artifact digest does not match the manifest")]
    ArtifactDigestMismatch(&'static str),
    #[error("the SQLite artifact belongs to another application")]
    WrongApplicationId,
    #[error("the SQLite integrity check failed")]
    IntegrityCheckFailed,
    #[error("the SQLite foreign-key check failed")]
    ForeignKeyViolation,
    #[error("the SQLite snapshot could not be finalized as a standalone artifact")]
    SnapshotFinalizationFailed,
    #[error("the controller identity does not match the backup manifest")]
    ControllerIdentityMismatch,
    #[error("durable signed artifacts do not match the controller identity or instance")]
    StoredControllerBindingMismatch,
    #[error("the backup high-water manifest does not match the SQLite artifact")]
    HighWaterMismatch,
    #[error("the recovery baseline belongs to another controller identity or instance")]
    RecoveryBaselineMismatch,
    #[error("the backup is older than the current controller high-water marks")]
    HighWaterRollback,
    #[error("the current controller is still running or another control operation owns its lock")]
    ControllerStillRunning,
    #[error("the system clock is before the Unix epoch")]
    Clock,
    #[error("controller database validation failed: {0}")]
    Database(#[from] crate::db::DatabaseError),
    #[error("controller identity validation failed")]
    Identity(#[from] IdentityError),
    #[error("SQLite operation failed")]
    Sqlite(#[from] rusqlite::Error),
    #[error("backup I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("backup manifest encoding failed")]
    Json(#[from] serde_json::Error),
    #[error("recovery was interrupted before atomic persistence")]
    Interrupted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use rusqlite::params;
    use tempfile::TempDir;

    fn initialized_controller(temp: &TempDir, name: &str) -> PathBuf {
        let path = temp.path().join(name);
        drop(Database::open(&path, "Backup Test").unwrap());
        path
    }

    fn options(source: &Path, destination: &Path) -> CreateBackupOptions {
        CreateBackupOptions {
            source_database: source.to_path_buf(),
            destination: destination.to_path_buf(),
            external_encryption: ExternalEncryptionContract::new("test-encrypted-volume").unwrap(),
        }
    }

    #[test]
    fn initialized_empty_controller_round_trips_and_dry_run_does_not_write() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        let report = create_backup(&options(&database, &backup)).unwrap();
        assert_eq!(report.database_schema_version, SCHEMA_VERSION);
        let destination = temp.path().join("restored");
        let restore = restore_backup(&RestoreOptions {
            backup,
            destination: destination.clone(),
            baseline: RestoreBaseline::CurrentDatabase(database),
            recovery_mode: RecoveryMode::Explicit,
            dry_run: true,
        })
        .unwrap();
        assert!(restore.verified);
        assert!(!restore.restored);
        assert!(!destination.exists());
    }

    #[test]
    fn online_backup_succeeds_while_control_owns_the_database() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("live.sqlite3");
        let live = Database::open(&database, "Live Backup Test").unwrap();
        let backup = temp.path().join("backup");
        let report = create_backup(&options(&database, &backup)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert_eq!(
            report.network_id,
            runtime.block_on(live.network()).unwrap().network_id
        );
        verify_backup(&backup).unwrap();
    }

    #[test]
    fn atomic_restore_creates_a_reopenable_owner_only_generation() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        let destination = temp.path().join("restored");
        let restore = restore_backup(&RestoreOptions {
            backup,
            destination: destination.clone(),
            baseline: RestoreBaseline::NoLocalHistory,
            recovery_mode: RecoveryMode::Explicit,
            dry_run: false,
        })
        .unwrap();
        assert!(restore.restored);
        let restored_database = destination.join(DATABASE_FILE);
        let reopened = Database::open(&restored_database, "ignored on existing database").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let network = runtime.block_on(reopened.network()).unwrap();
        assert_eq!(network.network_id, restore.network_id);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for path in [
                restored_database,
                destination.join(IDENTITY_FILE),
                destination.join(MANIFEST_FILE),
            ] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn empty_and_old_schema_databases_are_rejected() {
        let temp = TempDir::new().unwrap();
        for (name, user_version) in [("empty.sqlite3", 0), ("old.sqlite3", 1)] {
            let database = temp.path().join(name);
            let connection = Connection::open(&database).unwrap();
            connection
                .pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            connection
                .pragma_update(None, "user_version", user_version)
                .unwrap();
            drop(connection);
            ControllerIdentity::load_or_create(&database).unwrap();
            let result = create_backup(&options(
                &database,
                &temp.path().join(format!("{name}.backup")),
            ));
            assert!(result.is_err());
        }
    }

    #[test]
    fn corrupted_database_is_rejected_before_sqlite_is_opened() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        let artifact = backup.join(DATABASE_FILE);
        let mut bytes = fs::read(&artifact).unwrap();
        bytes[128] ^= 0xff;
        fs::write(&artifact, bytes).unwrap();
        assert!(matches!(
            verify_backup(&backup),
            Err(BackupError::ArtifactDigestMismatch("database"))
        ));
    }

    #[test]
    fn resealed_wrong_identity_is_rejected() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let other = initialized_controller(&temp, "other.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        fs::copy(identity_path(&other), backup.join(IDENTITY_FILE)).unwrap();
        let mut manifest = read_manifest(&backup.join(MANIFEST_FILE)).unwrap();
        manifest.payload.identity_sha256 = sha256_file(&backup.join(IDENTITY_FILE)).unwrap();
        let other_identity = ControllerIdentity::load_existing(&identity_path(&other)).unwrap();
        manifest = seal_manifest(manifest.payload, &other_identity).unwrap();
        fs::write(
            backup.join(MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_backup(&backup),
            Err(BackupError::ControllerIdentityMismatch)
        ));
    }

    #[test]
    fn rollback_high_water_is_rejected() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        let connection = Connection::open(&database).unwrap();
        let network_id: String = connection
            .query_row("SELECT network_id FROM networks", [], |row| row.get(0))
            .unwrap();
        connection
            .execute(
                "INSERT INTO audit_events(
                    network_id, actor_type, actor_id, event_type, target_type,
                    target_id, outcome, details_json, created_at
                 ) VALUES (?1, 'admin', NULL, 'test.advance', 'network', ?1,
                    'success', '{}', 1)",
                params![network_id],
            )
            .unwrap();
        drop(connection);
        let result = restore_backup(&RestoreOptions {
            backup,
            destination: temp.path().join("restored"),
            baseline: RestoreBaseline::CurrentDatabase(database),
            recovery_mode: RecoveryMode::Explicit,
            dry_run: false,
        });
        assert!(matches!(result, Err(BackupError::HighWaterRollback)));
    }

    #[test]
    fn recovery_refuses_a_running_baseline_controller() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        let _live = Database::open(&database, "Existing").unwrap();
        let result = restore_backup(&RestoreOptions {
            backup,
            destination: temp.path().join("restored"),
            baseline: RestoreBaseline::CurrentDatabase(database),
            recovery_mode: RecoveryMode::Explicit,
            dry_run: true,
        });
        assert!(matches!(result, Err(BackupError::ControllerStillRunning)));
    }

    #[test]
    fn interruption_and_existing_destination_never_replace_state() {
        let temp = TempDir::new().unwrap();
        let database = initialized_controller(&temp, "current.sqlite3");
        let backup = temp.path().join("backup");
        create_backup(&options(&database, &backup)).unwrap();
        let destination = temp.path().join("restored");
        let restore_options = RestoreOptions {
            backup,
            destination: destination.clone(),
            baseline: RestoreBaseline::CurrentDatabase(database),
            recovery_mode: RecoveryMode::Explicit,
            dry_run: false,
        };
        let interrupted =
            restore_backup_with_hook(&restore_options, || Err(BackupError::Interrupted));
        assert!(matches!(interrupted, Err(BackupError::Interrupted)));
        assert!(!destination.exists());

        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sentinel"), b"preserve").unwrap();
        assert!(matches!(
            restore_backup(&restore_options),
            Err(BackupError::DestinationExists)
        ));
        assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"preserve");
    }
}
