//! Persistent local foundation for the Reality Console node host.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, X25519PublicKey};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use x25519_dalek::{PublicKey as X25519DalekPublicKey, StaticSecret};
use zeroize::Zeroize as _;

const DATABASE_FILE: &str = "node-host.sqlite3";
const LOCK_FILE: &str = "node-host.lock";
const ED25519_SEED_FILE: &str = "identity.ed25519.seed";
const X25519_SEED_FILE: &str = "identity.x25519.seed";
const SEED_LENGTH: usize = 32;
const CURRENT_SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x4E48_4F53;
const MIGRATION_1_NAME: &str = "node_host_foundation";

const MIGRATION_1: &str = "
    CREATE TABLE host_config (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        controller_url TEXT NOT NULL
    ) STRICT;
";

/// Public, non-secret state suitable for CLI output and logs.
#[derive(Debug, Serialize)]
pub struct HostStatus {
    /// Configured controller origin.
    pub controller: Url,
    /// Public request-signing identity.
    pub identity_public_key: Ed25519PublicKey,
    /// Public recipient-encryption identity.
    pub encryption_public_key: X25519PublicKey,
    /// Applied database schema version.
    pub schema_version: i64,
}

/// A seed whose formatting can never reveal its bytes.
struct SecretSeed([u8; SEED_LENGTH]);

impl fmt::Debug for SecretSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Initializes a data directory, or verifies and reuses an existing one.
///
/// # Errors
///
/// Returns an error if the directory cannot be locked, persisted state is
/// invalid, migrations fail, or an existing controller differs.
pub fn initialize(data_dir: &Path, controller: &str) -> Result<HostStatus> {
    let controller = parse_controller(controller)?;
    let _lock = DataDirLock::acquire(data_dir, true)?;
    let mut connection = open_database(data_dir, true)?;
    migrate(&mut connection)?;
    configure_controller(&connection, &controller)?;
    let identity = Identity::load_or_create(data_dir)?;
    build_status(&connection, controller, &identity)
}

/// Reads initialized state while holding the data-directory lock.
///
/// # Errors
///
/// Returns an error if the host is not initialized, cannot be exclusively
/// locked, or contains invalid state.
pub fn status(data_dir: &Path) -> Result<HostStatus> {
    let _lock = DataDirLock::acquire(data_dir, false)?;
    let connection = open_database(data_dir, false)?;
    apply_pragmas(&connection)?;
    validate_migration_state(&connection)?;
    let controller_value: String = connection
        .query_row(
            "SELECT controller_url FROM host_config WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .context("node host is not initialized")?;
    let controller = parse_controller(&controller_value)?;
    let identity = Identity::load(data_dir)?;
    build_status(&connection, controller, &identity)
}

fn parse_controller(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("controller must be an absolute URL")?;
    let host = url
        .host_str()
        .context("controller URL must include a host")?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        bail!("controller must use https; http is allowed only for loopback development");
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("controller URL must be an origin without credentials, path, query, or fragment");
    }
    Url::parse(&url.origin().ascii_serialization()).context("controller origin is invalid")
}

fn open_database(data_dir: &Path, create: bool) -> Result<Connection> {
    let path = data_dir.join(DATABASE_FILE);
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection = Connection::open_with_flags(&path, flags)
        .with_context(|| format!("failed to open {}", path.display()))?;
    set_owner_only(&path)?;
    apply_pragmas(&connection)?;
    validate_application_id(&connection)?;
    Ok(connection)
}

fn apply_pragmas(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = FAST;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        ) STRICT;",
    )?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_migration_state(&transaction)?;
    let applied: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 1",
        [],
        |row| row.get(0),
    )?;
    if applied == 0 {
        let checksum = migration_checksum();
        transaction.execute_batch(MIGRATION_1)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at)
             VALUES (1, ?1, ?2, ?3)",
            params![MIGRATION_1_NAME, checksum, unix_timestamp()?],
        )?;
        transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    }
    transaction.commit()?;
    Ok(())
}

fn validate_application_id(connection: &Connection) -> Result<()> {
    let current: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    match current {
        0 => connection.pragma_update(None, "application_id", APPLICATION_ID)?,
        APPLICATION_ID => {}
        _ => bail!("database belongs to another application"),
    }
    Ok(())
}

fn validate_migration_state(connection: &Connection) -> Result<()> {
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version > CURRENT_SCHEMA_VERSION {
        bail!("database schema is newer than this node host supports");
    }
    let rows: Vec<(i64, String, String)> = {
        let mut statement = connection
            .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version")?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows
    };
    match rows.as_slice() {
        [] if user_version == 0 => Ok(()),
        [(1, name, checksum)]
            if user_version == 1
                && name == MIGRATION_1_NAME
                && checksum == &migration_checksum() =>
        {
            Ok(())
        }
        [] => bail!("schema migration history does not match PRAGMA user_version"),
        [(version, _, _)] if *version > CURRENT_SCHEMA_VERSION => {
            bail!("database schema is newer than this node host supports")
        }
        _ => bail!("schema migration history is invalid or has been modified"),
    }
}

fn migration_checksum() -> String {
    let mut hasher = Sha256::new();
    hasher.update(CURRENT_SCHEMA_VERSION.to_be_bytes());
    hasher.update(MIGRATION_1_NAME.as_bytes());
    hasher.update(MIGRATION_1.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}

fn unix_timestamp() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("current timestamp does not fit SQLite INTEGER")
}

fn configure_controller(connection: &Connection, controller: &Url) -> Result<()> {
    let existing = connection.query_row(
        "SELECT controller_url FROM host_config WHERE singleton = 1",
        [],
        |row| row.get::<_, String>(0),
    );
    match existing {
        Ok(existing) if existing == controller.as_str() => Ok(()),
        Ok(_) => bail!("node host is already initialized for a different controller"),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            connection.execute(
                "INSERT INTO host_config(singleton, controller_url) VALUES (1, ?1)",
                params![controller.as_str()],
            )?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn build_status(
    connection: &Connection,
    controller: Url,
    identity: &Identity,
) -> Result<HostStatus> {
    let schema_version = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    Ok(HostStatus {
        controller,
        identity_public_key: identity.ed25519_public()?,
        encryption_public_key: identity.x25519_public()?,
        schema_version,
    })
}

struct Identity {
    signing: SecretSeed,
    encryption: SecretSeed,
}

impl Identity {
    fn load_or_create(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            signing: load_or_create_seed(&data_dir.join(ED25519_SEED_FILE))?,
            encryption: load_or_create_seed(&data_dir.join(X25519_SEED_FILE))?,
        })
    }

    fn load(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            signing: load_seed(&data_dir.join(ED25519_SEED_FILE))?,
            encryption: load_seed(&data_dir.join(X25519_SEED_FILE))?,
        })
    }

    fn ed25519_public(&self) -> Result<Ed25519PublicKey> {
        URL_SAFE_NO_PAD
            .encode(
                SigningKey::from_bytes(&self.signing.0)
                    .verifying_key()
                    .to_bytes(),
            )
            .parse()
            .context("generated invalid Ed25519 public key")
    }

    fn x25519_public(&self) -> Result<X25519PublicKey> {
        let secret = StaticSecret::from(self.encryption.0);
        URL_SAFE_NO_PAD
            .encode(X25519DalekPublicKey::from(&secret).to_bytes())
            .parse()
            .context("generated invalid X25519 public key")
    }
}

fn load_or_create_seed(path: &Path) -> Result<SecretSeed> {
    if path.exists() {
        return load_seed(path);
    }
    let mut bytes = [0_u8; SEED_LENGTH];
    OsRng.fill_bytes(&mut bytes);
    atomic_write_owner_only(path, &bytes)?;
    load_seed(path)
}

fn load_seed(path: &Path) -> Result<SecretSeed> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    ensure_owner_only(path)?;
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let seed: [u8; SEED_LENGTH] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} has an invalid seed length", path.display()))?;
    Ok(SecretSeed(seed))
}

fn atomic_write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("seed path has no parent")?;
    let mut random = [0_u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".seed-{}.tmp", u64::from_ne_bytes(random)));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_create_owner_only(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to atomically create {}", path.display()))
}

struct DataDirLock {
    file: File,
}

impl DataDirLock {
    fn acquire(data_dir: &Path, create: bool) -> Result<Self> {
        if create {
            fs::create_dir_all(data_dir)?;
            set_directory_owner_only(data_dir)?;
        } else if !data_dir.is_dir() {
            bail!("node host is not initialized");
        }
        let path = data_dir.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(create);
        set_create_owner_only(&mut options);
        let file = options
            .open(&path)
            .context("node host is not initialized")?;
        set_owner_only(&path)?;
        file.try_lock_exclusive()
            .context("node host data directory is already in use")?;
        Ok(Self { file })
    }
}

impl Drop for DataDirLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
fn set_create_owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_create_owner_only(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!("{} must have permissions 0600", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_directory_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{open_database, SecretSeed};

    #[test]
    fn private_seed_debug_is_redacted() {
        let seed = SecretSeed([42; 32]);
        assert_eq!(format!("{seed:?}"), "[redacted]");
        assert!(!format!("{seed:?}").contains("42"));
    }

    #[test]
    fn configured_connection_uses_required_pragmas() {
        let temp = tempfile::tempdir().unwrap();
        let connection = open_database(temp.path(), true).unwrap();

        for (pragma, expected) in [
            ("foreign_keys", 1),
            ("synchronous", 2),
            ("trusted_schema", 0),
            ("secure_delete", 2),
        ] {
            let actual: i64 = connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(actual, expected, "unexpected PRAGMA {pragma}");
        }
    }
}
