use crate::{
    build_status, ensure_owner_only, load_or_create_seed, load_seed, migrate, open_database,
    parse_controller, set_create_owner_only, set_directory_owner_only, set_owner_only,
    unix_timestamp, DataDirLock, HostStatus, Identity, SecretSeed, REALITY_X25519_SEED_FILE,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Sha256Digest as ProtocolSha256Digest, X25519PublicKey};
use control_protocol::error::ErrorCode;
use control_protocol::id::{Revision, Timestamp};
use control_protocol::node::{RevisionResult, RevisionResultState, SignedDesiredState};
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use semver::Version;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};
use xray_runtime::{
    probe_version, test_config, ExecutionLimits, RealityPrivateKey, RealityTarget,
    RenderedXrayConfig, RuntimeError, ServerName, Sha256Digest as RuntimeSha256Digest, ShortId,
    StatsApiConfig, UserEmail, VlessRealityConfigBuilder, VlessUser, XrayBinarySpec,
};
use zeroize::Zeroizing;

const CONFIG_DIRECTORY: &str = "configs";
const MAX_STORED_CONFIG_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrayRuntimeStatus {
    pub binary_path: PathBuf,
    pub expected_sha256: String,
    pub version: String,
    pub reality_public_key: X25519PublicKey,
    pub reality_short_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedXrayCandidate {
    pub revision: Revision,
    pub config_path: PathBuf,
    pub config_digest: ProtocolSha256Digest,
    pub binary_path: PathBuf,
    pub binary_digest: RuntimeSha256Digest,
    pub listen_port: u16,
    pub public_port: Option<u16>,
}

/// Verifies and records an installer-provided Xray runtime without starting it.
///
/// The explicit binary is checked for safe file metadata and the caller's
/// trusted SHA-256, then queried with a bounded `xray version` subprocess. A
/// separate node-local REALITY identity is created only after those checks
/// succeed. Replacing an existing binary specification requires `replace`.
///
/// # Errors
///
/// Returns an error for an unsafe binary, invalid digest/path/version output,
/// conflicting persisted configuration, unsafe local identity material, or
/// persistence failure.
pub async fn configure_xray(
    data_dir: &Path,
    binary_path: &Path,
    expected_sha256: &str,
    replace: bool,
) -> Result<HostStatus> {
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
    let identity = Identity::load(&connection, data_dir)?;

    let digest = RuntimeSha256Digest::from_hex(expected_sha256)
        .context("expected Xray SHA-256 must contain 64 hexadecimal characters")?;
    let binary_path = binary_path
        .to_str()
        .context("Xray binary path must be valid UTF-8")?
        .to_owned();
    let expected_sha256 = digest.to_string();
    let existing = load_runtime_row(&connection)?;
    let stats_api_port = match existing.as_ref() {
        Some(runtime) => runtime.stats_api_port,
        None => reserve_stats_api_port()?,
    };
    let pin_changed = existing.as_ref().is_some_and(|stored| {
        stored.binary_path != binary_path || stored.expected_sha256 != expected_sha256
    });
    let digest_changed = existing
        .as_ref()
        .is_some_and(|stored| stored.expected_sha256 != expected_sha256);
    if pin_changed && !replace {
        bail!("Xray runtime is already configured; use --replace to change the pinned binary");
    }
    if digest_changed {
        let validated_configs: i64 =
            connection.query_row("SELECT COUNT(*) FROM rendered_xray_configs", [], |row| {
                row.get(0)
            })?;
        if validated_configs != 0 {
            bail!("Xray runtime cannot be replaced while validated revisions are retained");
        }
    }

    let spec = XrayBinarySpec::new(binary_path.clone(), digest)
        .context("Xray binary path must be an explicit absolute path")?;
    let verified = tokio::task::spawn_blocking(move || spec.verify())
        .await
        .context("Xray binary verification task failed")?
        .context("Xray binary verification failed")?;
    let version_probe = probe_version(&verified, ExecutionLimits::default())
        .await
        .context("Xray version probe failed")?;
    let version = normalize_version(version_probe.stdout())?;
    let reality_seed_path = data_dir.join(REALITY_X25519_SEED_FILE);
    let reality_seed = if existing.is_some() {
        load_seed(&reality_seed_path).context("stored REALITY identity is unavailable")?
    } else {
        load_or_create_seed(&reality_seed_path).context("failed to create REALITY identity")?
    };
    validate_reality_seed(&reality_seed)?;

    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    match existing {
        Some(stored)
            if stored.binary_path == binary_path
                && stored.expected_sha256 == expected_sha256
                && stored.version == version => {}
        Some(_) => {
            transaction.execute(
                "UPDATE xray_runtime_config
                 SET binary_path = ?1, expected_sha256 = ?2, version = ?3, updated_at = ?4
                 WHERE singleton = 1",
                params![binary_path, expected_sha256, version, now],
            )?;
        }
        None => {
            transaction.execute(
                "INSERT INTO xray_runtime_config(
                    singleton, binary_path, expected_sha256, version, configured_at, updated_at,
                    stats_api_port
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?4, ?5)",
                params![binary_path, expected_sha256, version, now, stats_api_port],
            )?;
        }
    }
    transaction.commit()?;
    build_status(&connection, data_dir, controller, &identity)
}

/// Renders and validates one verified desired-state artifact without activating it.
///
/// A missing local Xray runtime leaves the revision in `received`. Deterministic
/// incompatibility or configuration failures append a terminal `rejected`
/// result. Local binary, process, and filesystem failures remain retryable and
/// therefore do not rewrite controller state as a permanent rejection.
pub(crate) async fn validate_desired_state(
    data_dir: &Path,
    connection: &mut Connection,
    envelope: &SignedDesiredState,
) -> Result<()> {
    let revision = envelope.document.revision;
    if validation_is_complete(connection, data_dir, revision)? {
        return Ok(());
    }

    let Some(runtime) = load_runtime_row(connection)? else {
        return Ok(());
    };
    let started_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
    if let Some(error_code) = minimum_agent_version_error(&envelope.document.min_agent_version)? {
        append_rejected_result(connection, revision, started_at, error_code)?;
        return Ok(());
    }

    let runtime_digest = RuntimeSha256Digest::from_hex(&runtime.expected_sha256)
        .context("stored Xray runtime checksum is invalid")?;
    let spec = XrayBinarySpec::new(runtime.binary_path.clone(), runtime_digest)
        .context("stored Xray runtime path is invalid")?;
    let verified = tokio::task::spawn_blocking(move || spec.verify())
        .await
        .context("Xray binary verification task failed")?
        .context("pinned Xray binary verification failed")?;

    let reality_seed = load_seed(&data_dir.join(REALITY_X25519_SEED_FILE))
        .context("stored REALITY identity is unavailable")?;
    validate_reality_seed(&reality_seed)?;
    let Ok(rendered) = render_desired_config(envelope, &reality_seed, runtime.stats_api_port)
    else {
        append_rejected_result(
            connection,
            revision,
            started_at,
            ErrorCode::ValidationFailed,
        )?;
        return Ok(());
    };

    match test_config(&verified, &rendered, ExecutionLimits::default()).await {
        Ok(_) => {}
        Err(RuntimeError::NonZeroExit { .. } | RuntimeError::ConfigTooLarge) => {
            append_rejected_result(
                connection,
                revision,
                started_at,
                ErrorCode::ValidationFailed,
            )?;
            return Ok(());
        }
        Err(error) => return Err(error).context("pinned Xray config test failed"),
    }

    let config_digest = protocol_digest(rendered.expose_json().as_bytes());
    let relative_path = persist_immutable_config(data_dir, revision, &rendered, &config_digest)?;
    append_validated_result(
        connection,
        revision,
        started_at,
        &relative_path,
        &config_digest,
        &runtime.expected_sha256,
    )
}

pub(crate) fn configured_xray_version(connection: &Connection) -> Result<Option<String>> {
    Ok(load_runtime_row(connection)?.map(|runtime| runtime.version))
}

pub(crate) fn load_validated_candidate(
    connection: &Connection,
    data_dir: &Path,
    revision: Revision,
) -> Result<ValidatedXrayCandidate> {
    let reports = load_revision_results(connection, revision)?;
    let latest = reports
        .last()
        .map(|(_, report)| report)
        .context("validated Xray candidate has no revision result")?;
    if !matches!(
        latest.state,
        RevisionResultState::Validated | RevisionResultState::Applied
    ) {
        bail!("revision is not eligible to run as an Xray candidate");
    }
    verify_rendered_config(connection, data_dir, revision, latest)?;
    let rendered = load_rendered_config_row(connection, revision)?;
    let runtime =
        load_runtime_row(connection)?.context("validated candidate has no Xray runtime")?;
    if runtime.expected_sha256 != rendered.binary_digest {
        bail!("validated candidate was tested with a different pinned Xray binary");
    }
    let config_digest: ProtocolSha256Digest = rendered
        .config_digest
        .parse()
        .context("validated candidate config digest is invalid")?;
    let binary_digest = RuntimeSha256Digest::from_hex(&rendered.binary_digest)
        .context("validated candidate binary digest is invalid")?;
    let expected_relative = config_relative_path(revision);
    if Path::new(&rendered.relative_path) != expected_relative {
        bail!("validated candidate config path is invalid");
    }
    let config_path = fs::canonicalize(data_dir.join(expected_relative))
        .context("validated candidate config path is unavailable")?;
    let envelope_json: String = connection
        .query_row(
            "SELECT envelope_json FROM desired_state_artifacts WHERE revision = ?1",
            [revision.get()],
            |row| row.get(0),
        )
        .context("validated candidate desired-state artifact is missing")?;
    let envelope: SignedDesiredState = serde_json::from_str(&envelope_json)
        .context("validated candidate desired-state artifact is invalid")?;
    if envelope.document.revision != revision {
        bail!("validated candidate desired-state revision is inconsistent");
    }
    Ok(ValidatedXrayCandidate {
        revision,
        config_path,
        config_digest,
        binary_path: PathBuf::from(runtime.binary_path),
        binary_digest,
        listen_port: envelope.document.xray.listen_port,
        public_port: envelope.document.xray.public_port,
    })
}

pub(crate) fn load_xray_runtime_status(
    connection: &Connection,
    data_dir: &Path,
) -> Result<Option<XrayRuntimeStatus>> {
    let Some(stored) = load_runtime_row(connection)? else {
        return Ok(None);
    };
    let seed = load_seed(&data_dir.join(REALITY_X25519_SEED_FILE))
        .context("stored REALITY identity is unavailable")?;
    let (public_key, short_id) = reality_public_material(&seed)?;
    Ok(Some(XrayRuntimeStatus {
        binary_path: PathBuf::from(stored.binary_path),
        expected_sha256: stored.expected_sha256,
        version: stored.version,
        reality_public_key: public_key,
        reality_short_id: short_id,
    }))
}

#[derive(Debug)]
struct StoredRuntimeRow {
    binary_path: String,
    expected_sha256: String,
    version: String,
    stats_api_port: u16,
}

fn load_runtime_row(connection: &Connection) -> Result<Option<StoredRuntimeRow>> {
    let has_table: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'xray_runtime_config'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(None);
    }
    connection
        .query_row(
            "SELECT binary_path, expected_sha256, version, stats_api_port
             FROM xray_runtime_config WHERE singleton = 1",
            [],
            |row| {
                Ok(StoredRuntimeRow {
                    binary_path: row.get(0)?,
                    expected_sha256: row.get(1)?,
                    version: row.get(2)?,
                    stats_api_port: row.get::<_, i64>(3)?.try_into().map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn minimum_agent_version_error(required: &str) -> Result<Option<ErrorCode>> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .context("Node Host package version is not semantic")?;
    let Ok(required) = Version::parse(required) else {
        return Ok(Some(ErrorCode::SchemaUnsupported));
    };
    Ok((required > current).then_some(ErrorCode::SchemaUnsupported))
}

fn render_desired_config(
    envelope: &SignedDesiredState,
    reality_seed: &SecretSeed,
    stats_api_port: u16,
) -> Result<RenderedXrayConfig> {
    let encoded_private_key = Zeroizing::new(URL_SAFE_NO_PAD.encode(reality_seed.0));
    let private_key = RealityPrivateKey::parse(&encoded_private_key)
        .context("stored REALITY private key is invalid")?;
    let (_, short_id) = reality_public_material(reality_seed)?;
    let short_id = ShortId::parse(&short_id).context("stored REALITY short ID is invalid")?;
    let (target_host, target_port) = envelope
        .document
        .xray
        .target
        .rsplit_once(':')
        .context("desired REALITY target is invalid")?;
    let target_port = target_port
        .parse::<u16>()
        .context("desired REALITY target port is invalid")?;
    let target = RealityTarget::new(target_host, target_port)
        .context("desired REALITY target is invalid")?;
    let mut builder = VlessRealityConfigBuilder::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        envelope.document.xray.listen_port,
        target,
        private_key,
    )?
    .short_id(short_id)
    .stats_api(StatsApiConfig::loopback(stats_api_port)?);

    for server_name in &envelope.document.xray.server_names {
        builder = builder.server_name(
            ServerName::parse(server_name).context("desired REALITY server name is invalid")?,
        );
    }
    for desired_user in &envelope.document.users {
        let user_id = Uuid::parse_str(desired_user.vless_uuid.expose_secret())
            .context("desired VLESS UUID is invalid")?;
        let email = UserEmail::parse(&format!("user-{}", desired_user.user_id))
            .context("desired user identity cannot be represented safely")?;
        builder = builder.user(VlessUser::new(user_id, email, desired_user.enabled)?);
    }
    builder
        .build()
        .context("desired state cannot be rendered as an Xray configuration")
}

fn reserve_stats_api_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("failed to reserve a loopback Xray Stats API port")?;
    let port = listener
        .local_addr()
        .context("failed to inspect the reserved Xray Stats API port")?
        .port();
    drop(listener);
    Ok(port)
}

fn validation_is_complete(
    connection: &Connection,
    data_dir: &Path,
    revision: Revision,
) -> Result<bool> {
    let reports = load_revision_results(connection, revision)?;
    let Some((_, first)) = reports.first() else {
        bail!("desired-state revision is missing its received result");
    };
    if first.state != RevisionResultState::Received {
        bail!("desired-state revision result history does not begin with received");
    }
    let mut previous: Option<&RevisionResult> = None;
    for (_, report) in &reports {
        report
            .validate_transition_from(previous)
            .context("stored revision result transition is invalid")?;
        previous = Some(report);
    }
    let latest = reports.last().expect("received result exists").1.clone();
    match latest.state {
        RevisionResultState::Received => Ok(false),
        RevisionResultState::Validated | RevisionResultState::Applied => {
            verify_rendered_config(connection, data_dir, revision, &latest)?;
            Ok(true)
        }
        RevisionResultState::Rejected | RevisionResultState::RolledBack => Ok(true),
    }
}

fn load_revision_results(
    connection: &Connection,
    revision: Revision,
) -> Result<Vec<(String, RevisionResult)>> {
    let mut statement = connection.prepare(
        "SELECT report_json, report_digest
         FROM local_revision_results
         WHERE revision = ?1
         ORDER BY CASE state
             WHEN 'received' THEN 10
             WHEN 'validated' THEN 20
             ELSE 30
         END, state",
    )?;
    let rows = statement
        .query_map([revision.get()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(report_json, stored_digest)| {
            if protocol_digest(report_json.as_bytes()).as_str() != stored_digest {
                bail!("stored revision result digest is invalid");
            }
            let report: RevisionResult =
                serde_json::from_str(&report_json).context("stored revision result is invalid")?;
            report
                .validate(revision)
                .context("stored revision result failed validation")?;
            Ok((stored_digest, report))
        })
        .collect()
}

fn verify_rendered_config(
    connection: &Connection,
    data_dir: &Path,
    revision: Revision,
    report: &RevisionResult,
) -> Result<()> {
    let stored = load_rendered_config_row(connection, revision)?;
    let expected_relative = config_relative_path(revision);
    if Path::new(&stored.relative_path) != expected_relative {
        bail!("stored rendered Xray config path is invalid");
    }
    if report
        .config_digest
        .as_ref()
        .map(ProtocolSha256Digest::as_str)
        != Some(stored.config_digest.as_str())
    {
        bail!("validated revision config digest is inconsistent");
    }
    RuntimeSha256Digest::from_hex(&stored.binary_digest)
        .context("validated revision has an invalid historical Xray binary digest")?;
    verify_config_file(&data_dir.join(expected_relative), &stored.config_digest)
}

#[derive(Debug)]
struct RenderedConfigRow {
    relative_path: String,
    config_digest: String,
    binary_digest: String,
}

fn load_rendered_config_row(
    connection: &Connection,
    revision: Revision,
) -> Result<RenderedConfigRow> {
    connection
        .query_row(
            "SELECT relative_path, config_digest, binary_digest
             FROM rendered_xray_configs WHERE revision = ?1",
            [revision.get()],
            |row| {
                Ok(RenderedConfigRow {
                    relative_path: row.get(0)?,
                    config_digest: row.get(1)?,
                    binary_digest: row.get(2)?,
                })
            },
        )
        .optional()?
        .context("validated revision is missing its rendered Xray config metadata")
}

fn append_rejected_result(
    connection: &mut Connection,
    revision: Revision,
    started_at: Timestamp,
    error_code: ErrorCode,
) -> Result<()> {
    let result = RevisionResult {
        state: RevisionResultState::Rejected,
        config_digest: None,
        started_at,
        completed_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
        error_code: Some(error_code),
        rollback_revision: None,
    };
    append_revision_result(connection, revision, &result)
}

fn append_validated_result(
    connection: &mut Connection,
    revision: Revision,
    started_at: Timestamp,
    relative_path: &Path,
    config_digest: &ProtocolSha256Digest,
    binary_digest: &str,
) -> Result<()> {
    let completed_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
    let result = RevisionResult {
        state: RevisionResultState::Validated,
        config_digest: Some(config_digest.clone()),
        started_at,
        completed_at,
        error_code: None,
        rollback_revision: None,
    };
    let relative_path = relative_path
        .to_str()
        .context("rendered Xray config path is not UTF-8")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO rendered_xray_configs(
            revision, relative_path, config_digest, binary_digest, validated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            revision.get(),
            relative_path,
            config_digest.as_str(),
            binary_digest,
            completed_at.as_datetime().unix_timestamp(),
        ],
    )?;
    insert_revision_result(&transaction, revision, &result)?;
    transaction.commit()?;
    Ok(())
}

fn append_revision_result(
    connection: &mut Connection,
    revision: Revision,
    result: &RevisionResult,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_revision_result(&transaction, revision, result)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn insert_revision_result(
    connection: &Connection,
    revision: Revision,
    result: &RevisionResult,
) -> Result<()> {
    result
        .validate(revision)
        .context("generated revision result is invalid")?;
    let report_json = serde_json::to_string(result).context("failed to encode revision result")?;
    let report_digest = protocol_digest(report_json.as_bytes());
    validate_result_transition(connection, revision, result)?;
    connection.execute(
        "INSERT INTO local_revision_results(
            revision, state, report_json, report_digest, reported_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
        params![
            revision.get(),
            revision_state_name(result.state),
            report_json,
            report_digest.as_str(),
            result.completed_at.as_datetime().unix_timestamp(),
        ],
    )?;
    Ok(())
}

fn validate_result_transition(
    connection: &Connection,
    revision: Revision,
    candidate: &RevisionResult,
) -> Result<()> {
    let previous = load_revision_results(connection, revision)?
        .last()
        .map(|(_, report)| report.clone());
    candidate
        .validate_transition_from(previous.as_ref())
        .context("revision result transition is invalid")
}

fn persist_immutable_config(
    data_dir: &Path,
    revision: Revision,
    config: &RenderedXrayConfig,
    digest: &ProtocolSha256Digest,
) -> Result<PathBuf> {
    let directory = data_dir.join(CONFIG_DIRECTORY);
    ensure_private_directory(&directory)?;
    let relative_path = config_relative_path(revision);
    let final_path = data_dir.join(&relative_path);
    if final_path.try_exists()? {
        verify_config_file(&final_path, digest.as_str())?;
        return Ok(relative_path);
    }

    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = directory.join(format!(
        ".revision-{}-{}.tmp",
        revision.get(),
        u64::from_ne_bytes(random)
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_create_owner_only(&mut options);
        let mut file = options.open(&temporary)?;
        set_owner_only(&temporary)?;
        file.write_all(config.expose_json().as_bytes())?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_config_file(&final_path, digest.as_str())?;
            }
            Err(error) => return Err(error.into()),
        }
        fs::remove_file(&temporary)?;
        File::open(&directory)?.sync_all()?;
        verify_config_file(&final_path, digest.as_str())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("failed to persist immutable rendered Xray config")?;
    Ok(relative_path)
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("rendered Xray config directory is unsafe");
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error.into()),
    }
    set_directory_owner_only(path)
}

fn verify_config_file(path: &Path, expected_digest: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("failed to inspect rendered Xray config")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("rendered Xray config must be a regular non-symlink file");
    }
    if metadata.len() == 0 || metadata.len() > MAX_STORED_CONFIG_BYTES {
        bail!("rendered Xray config size is invalid");
    }
    ensure_owner_only(path)?;
    let contents = Zeroizing::new(fs::read(path).context("failed to read rendered Xray config")?);
    if protocol_digest(&contents).as_str() != expected_digest {
        bail!("rendered Xray config digest is invalid");
    }
    Ok(())
}

fn config_relative_path(revision: Revision) -> PathBuf {
    PathBuf::from(CONFIG_DIRECTORY).join(format!("revision-{}.json", revision.get()))
}

fn protocol_digest(value: &[u8]) -> ProtocolSha256Digest {
    ProtocolSha256Digest::from_bytes(Sha256::digest(value).into())
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

fn normalize_version(output: &str) -> Result<String> {
    let version = output.lines().next().unwrap_or_default().trim();
    let release = version
        .strip_prefix("Xray ")
        .and_then(|value| value.split_ascii_whitespace().next());
    let valid_release = release.is_some_and(|value| {
        let components: Vec<_> = value.split('.').collect();
        components.len() == 3
            && components.iter().all(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            })
    });
    if version.is_empty()
        || version.len() > 256
        || !version.is_ascii()
        || version.chars().any(char::is_control)
        || !valid_release
    {
        bail!("Xray version output is invalid");
    }
    Ok(format!(
        "Xray {}",
        release.expect("validated release exists")
    ))
}

fn validate_reality_seed(seed: &SecretSeed) -> Result<()> {
    let encoded = URL_SAFE_NO_PAD.encode(seed.0);
    RealityPrivateKey::parse(&encoded).context("stored REALITY private key is invalid")?;
    reality_public_material(seed)?;
    Ok(())
}

fn reality_public_material(seed: &SecretSeed) -> Result<(X25519PublicKey, String)> {
    let secret = StaticSecret::from(seed.0);
    let public_key: X25519PublicKey = URL_SAFE_NO_PAD
        .encode(X25519DalekPublicKey::from(&secret).to_bytes())
        .parse()
        .context("failed to encode REALITY public key")?;
    let mut hasher = Sha256::new();
    hasher.update(b"node-host/reality-short-id/v1");
    hasher.update(seed.0);
    let digest = hasher.finalize();
    let short_id = digest[..8]
        .iter()
        .fold(String::with_capacity(16), |mut value, byte| {
            write!(value, "{byte:02x}").expect("writing to a string cannot fail");
            value
        });
    ShortId::parse(&short_id).context("failed to derive REALITY short ID")?;
    Ok((public_key, short_id))
}

#[cfg(test)]
mod tests {
    use super::{minimum_agent_version_error, normalize_version};
    use control_protocol::error::ErrorCode;

    #[test]
    fn version_output_uses_one_bounded_safe_line() {
        assert_eq!(
            normalize_version("Xray 25.7.1\nA unified platform").unwrap(),
            "Xray 25.7.1"
        );
        assert_eq!(
            normalize_version(
                "Xray 26.3.27 (Xray, Penetrates Everything.) Custom (go1.26.1 darwin/arm64)"
            )
            .unwrap(),
            "Xray 26.3.27"
        );
        assert!(normalize_version("").is_err());
        assert!(normalize_version("Xray\t25").is_err());
        assert!(normalize_version("not-xray 25.7.1").is_err());
        assert!(normalize_version("Xray 25.7").is_err());
    }

    #[test]
    fn minimum_agent_version_is_closed_and_semantic() {
        assert_eq!(minimum_agent_version_error("0.1.0").unwrap(), None);
        assert_eq!(
            minimum_agent_version_error("999.0.0").unwrap(),
            Some(ErrorCode::SchemaUnsupported)
        );
        assert_eq!(
            minimum_agent_version_error("latest").unwrap(),
            Some(ErrorCode::SchemaUnsupported)
        );
    }
}
