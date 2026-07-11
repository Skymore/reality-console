use crate::{
    build_status, load_or_create_seed, load_seed, migrate, open_database, parse_controller,
    unix_timestamp, DataDirLock, HostStatus, Identity, SecretSeed, REALITY_X25519_SEED_FILE,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::X25519PublicKey;
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};
use xray_runtime::{
    probe_version, ExecutionLimits, RealityPrivateKey, Sha256Digest, ShortId, XrayBinarySpec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XrayRuntimeStatus {
    pub binary_path: PathBuf,
    pub expected_sha256: String,
    pub version: String,
    pub reality_public_key: X25519PublicKey,
    pub reality_short_id: String,
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
    let identity = Identity::load(data_dir)?;

    let digest = Sha256Digest::from_hex(expected_sha256)
        .context("expected Xray SHA-256 must contain 64 hexadecimal characters")?;
    let binary_path = binary_path
        .to_str()
        .context("Xray binary path must be valid UTF-8")?
        .to_owned();
    let expected_sha256 = digest.to_string();
    let existing = load_runtime_row(&connection)?;
    if existing.as_ref().is_some_and(|stored| {
        (stored.binary_path != binary_path || stored.expected_sha256 != expected_sha256) && !replace
    }) {
        bail!("Xray runtime is already configured; use --replace to change the pinned binary");
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
                    singleton, binary_path, expected_sha256, version, configured_at, updated_at
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?4)",
                params![binary_path, expected_sha256, version, now],
            )?;
        }
    }
    transaction.commit()?;
    build_status(&connection, data_dir, controller, &identity)
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
            "SELECT binary_path, expected_sha256, version
             FROM xray_runtime_config WHERE singleton = 1",
            [],
            |row| {
                Ok(StoredRuntimeRow {
                    binary_path: row.get(0)?,
                    expected_sha256: row.get(1)?,
                    version: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
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
    Ok(version.to_owned())
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
    use super::normalize_version;

    #[test]
    fn version_output_uses_one_bounded_safe_line() {
        assert_eq!(
            normalize_version("Xray 25.7.1\nA unified platform").unwrap(),
            "Xray 25.7.1"
        );
        assert!(normalize_version("").is_err());
        assert!(normalize_version("Xray\t25").is_err());
        assert!(normalize_version("not-xray 25.7.1").is_err());
        assert!(normalize_version("Xray 25.7").is_err());
    }
}
