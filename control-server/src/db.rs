use crate::config::{validate_network_name, ConfigError};
use crate::identity::{set_owner_only, ControllerIdentity, IdentityError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, verify_enrollment_proof,
    EnrollmentCryptoError, EnrollmentInvitation,
};
use control_protocol::id::{
    ControllerInstanceId, NetworkId, NodeId, NodeInvitationId, NodeKeyId, Timestamp,
};
use control_protocol::node::{
    CreateNodeInvitationRequest, CreateNodeInvitationResponse, EnrollNodeRequest,
    EnrollNodeResponse, NodeAuthenticationMode, NodeCredential, PairingPurpose,
};
use control_protocol::secret::Secret;
use control_protocol::validation::ProtocolValidationError;
use fs2::FileExt;
use rand_core::{OsRng, RngCore as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x5243_4F4E;
const INVITATION_SECRET_BYTES: usize = 32;
const NODE_CREDENTIAL_LIFETIME_DAYS: i64 = 90;

const MIGRATION_1_SQL: &str = r"
CREATE TABLE networks (
    network_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('active', 'recovery', 'disabled')),
    last_revision INTEGER NOT NULL DEFAULT 0 CHECK(last_revision >= 0),
    controller_epoch TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX networks_singleton ON networks ((1));
";

const MIGRATION_2_SQL: &str = r"
CREATE TABLE node_invitations (
    invitation_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK(purpose = 'node-enrollment'),
    intended_display_name TEXT NOT NULL CHECK(length(intended_display_name) BETWEEN 1 AND 128),
    secret_verifier BLOB NOT NULL UNIQUE CHECK(length(secret_verifier) = 32),
    controller_origin TEXT NOT NULL,
    controller_fingerprint TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    consumed_node_id TEXT,
    cancelled_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK(consumed_at IS NULL OR consumed_node_id IS NOT NULL),
    CHECK(NOT (consumed_at IS NOT NULL AND cancelled_at IS NOT NULL))
) STRICT;

CREATE INDEX node_invitations_expiry ON node_invitations(expires_at)
    WHERE consumed_at IS NULL AND cancelled_at IS NULL;

CREATE TABLE nodes (
    node_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'disabled', 'revoked')),
    agent_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
    identity_public_key TEXT NOT NULL UNIQUE,
    encryption_public_key TEXT NOT NULL UNIQUE,
    consent_policy_version TEXT NOT NULL,
    consent_host_owner INTEGER NOT NULL CHECK(consent_host_owner IN (0, 1)),
    consent_exit_ip INTEGER NOT NULL CHECK(consent_exit_ip IN (0, 1)),
    consent_accepted_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(network_id, node_id)
) STRICT;

CREATE TABLE node_auth_credentials (
    network_id TEXT NOT NULL REFERENCES networks(network_id) ON DELETE CASCADE,
    node_credential_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    identity_public_key TEXT NOT NULL,
    auth_mode TEXT NOT NULL CHECK(auth_mode = 'signedRequest'),
    not_before INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    rotation_parent_id TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(network_id, node_credential_id),
    UNIQUE(network_id, node_id, identity_public_key),
    FOREIGN KEY(network_id, node_id) REFERENCES nodes(network_id, node_id) ON DELETE CASCADE,
    FOREIGN KEY(network_id, rotation_parent_id)
        REFERENCES node_auth_credentials(network_id, node_credential_id)
) STRICT;

CREATE TABLE audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT REFERENCES networks(network_id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    event_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'rejected', 'failure')),
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX audit_events_created_at ON audit_events(created_at);
";

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "control_service_foundation",
        sql: MIGRATION_1_SQL,
    },
    Migration {
        version: 2,
        name: "node_enrollment",
        sql: MIGRATION_2_SQL,
    },
];

#[derive(Clone)]
pub struct Database {
    inner: Arc<Mutex<DatabaseInner>>,
    controller_identity: ControllerIdentity,
}

struct DatabaseInner {
    connection: Connection,
    _lock: File,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkRecord {
    pub network_id: String,
    pub display_name: String,
    pub status: String,
    pub last_revision: i64,
    pub controller_epoch: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Enrollment response plus whether this request created the durable node.
pub struct NodeEnrollmentResult {
    pub response: EnrollNodeResponse,
    pub created: bool,
}

impl Database {
    /// Opens the exclusively owned database, migrates it, and bootstraps its network.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid configuration, another live
    /// owner, incompatible migration history, failed integrity checks, or I/O.
    pub fn open(path: &Path, network_display_name: &str) -> Result<Self, DatabaseError> {
        validate_network_name(network_display_name)?;
        prepare_parent(path)?;
        prepare_owner_only_file(path)?;
        let lock = acquire_lock(path)?;
        let controller_identity = ControllerIdentity::load_or_create(path)?;
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        configure_connection(&connection)?;
        validate_application_id(&connection)?;
        migrate(&mut connection)?;
        bootstrap_network(&mut connection, network_display_name)?;
        verify_database(&connection)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(DatabaseInner {
                connection,
                _lock: lock,
            })),
            controller_identity,
        })
    }

    /// Loads the singleton network without blocking the async executor.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] when the blocking worker, ownership mutex, or
    /// `SQLite` query fails.
    pub async fn network(&self) -> Result<NetworkRecord, DatabaseError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            load_network(&guard.connection)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Creates a high-entropy one-time node invitation.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for validation, clock, or storage failures.
    pub async fn create_node_invitation(
        &self,
        request: CreateNodeInvitationRequest,
        controller_origin: String,
    ) -> Result<CreateNodeInvitationResponse, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            create_node_invitation(
                &mut guard.connection,
                &identity,
                &request,
                &controller_origin,
            )
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    /// Atomically consumes an invitation and creates the node and first key.
    ///
    /// # Errors
    ///
    /// Returns [`DatabaseError`] for invalid invitations or proofs, validation,
    /// clock, and storage failures.
    pub async fn enroll_node(
        &self,
        request: EnrollNodeRequest,
    ) -> Result<NodeEnrollmentResult, DatabaseError> {
        request.validate()?;
        let identity = self.controller_identity.clone();
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let mut guard = inner.lock().map_err(|_| DatabaseError::LockPoisoned)?;
            enroll_node(&mut guard.connection, &identity, &request)
        })
        .await
        .map_err(DatabaseError::Worker)?
    }

    #[must_use]
    pub fn controller_identity(&self) -> ControllerIdentity {
        self.controller_identity.clone()
    }
}

fn prepare_parent(path: &Path) -> Result<(), DatabaseError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<File, DatabaseError> {
    let lock_path = lock_path(path);
    let lock = owner_only_open_options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    set_owner_only(&lock_path)?;
    lock.try_lock_exclusive()
        .map_err(|source| DatabaseError::DatabaseLocked { lock_path, source })?;
    Ok(lock)
}

fn prepare_owner_only_file(path: &Path) -> Result<(), DatabaseError> {
    let file = owner_only_open_options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.sync_all()?;
    set_owner_only(path)?;
    Ok(())
}

fn owner_only_open_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
}

fn lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn configure_connection(connection: &Connection) -> Result<(), DatabaseError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 5000;
         PRAGMA trusted_schema = OFF;
         PRAGMA secure_delete = FAST;",
    )?;
    Ok(())
}

fn validate_application_id(connection: &Connection) -> Result<(), DatabaseError> {
    let current: i64 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    match current {
        0 => connection.pragma_update(None, "application_id", APPLICATION_ID)?,
        APPLICATION_ID => {}
        actual => {
            return Err(DatabaseError::WrongApplicationId {
                expected: APPLICATION_ID,
                actual,
            });
        }
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), DatabaseError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        ) STRICT;",
    )?;

    let applied = load_applied_migrations(connection)?;
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let highest_applied = applied.keys().next_back().copied().unwrap_or(0);

    if highest_applied > SCHEMA_VERSION || user_version > SCHEMA_VERSION {
        return Err(DatabaseError::SchemaTooNew {
            supported: SCHEMA_VERSION,
            actual: highest_applied.max(user_version),
        });
    }
    if user_version != highest_applied {
        return Err(DatabaseError::MigrationMirrorMismatch {
            source_version: highest_applied,
            user_version,
        });
    }

    for expected_version in 1..=highest_applied {
        if !applied.contains_key(&expected_version) {
            return Err(DatabaseError::MigrationGap {
                version: expected_version,
            });
        }
    }

    let mut current_version = highest_applied;
    for migration in MIGRATIONS {
        let expected_checksum = migration_checksum(migration);
        if let Some((name, checksum)) = applied.get(&migration.version) {
            if name != migration.name || checksum != &expected_checksum {
                return Err(DatabaseError::MigrationChecksumMismatch {
                    version: migration.version,
                });
            }
            continue;
        }

        if migration.version != current_version + 1 {
            return Err(DatabaseError::MigrationGap {
                version: migration.version,
            });
        }

        let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                migration.version,
                migration.name,
                expected_checksum,
                unix_timestamp()?
            ],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
        current_version = migration.version;
    }

    Ok(())
}

fn load_applied_migrations(
    connection: &Connection,
) -> Result<BTreeMap<i64, (String, String)>, DatabaseError> {
    let mut statement = connection
        .prepare("SELECT version, name, checksum FROM schema_migrations ORDER BY version ASC")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut applied = BTreeMap::new();
    for row in rows {
        let (version, name, checksum) = row?;
        applied.insert(version, (name, checksum));
    }
    Ok(applied)
}

fn migration_checksum(migration: &Migration) -> String {
    let mut hasher = Sha256::new();
    hasher.update(migration.version.to_be_bytes());
    hasher.update(migration.name.as_bytes());
    hasher.update(migration.sql.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut checksum, byte| {
            write!(checksum, "{byte:02x}").expect("writing to a string cannot fail");
            checksum
        })
}

fn bootstrap_network(
    connection: &mut Connection,
    network_display_name: &str,
) -> Result<(), DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM networks", [], |row| row.get(0))?;
    match count {
        0 => {
            let now = unix_timestamp()?;
            transaction.execute(
                "INSERT INTO networks(
                    network_id, display_name, status, last_revision, controller_epoch,
                    created_at, updated_at
                 ) VALUES (?1, ?2, 'active', 0, ?3, ?4, ?4)",
                params![
                    Uuid::new_v4().hyphenated().to_string(),
                    network_display_name,
                    Uuid::new_v4().hyphenated().to_string(),
                    now
                ],
            )?;
        }
        1 => {}
        actual => return Err(DatabaseError::MultipleNetworks(actual)),
    }
    transaction.commit()?;
    Ok(())
}

fn load_network(connection: &Connection) -> Result<NetworkRecord, DatabaseError> {
    connection
        .query_row(
            "SELECT network_id, display_name, status, last_revision, controller_epoch,
                    created_at, updated_at
             FROM networks",
            [],
            |row| {
                Ok(NetworkRecord {
                    network_id: row.get(0)?,
                    display_name: row.get(1)?,
                    status: row.get(2)?,
                    last_revision: row.get(3)?,
                    controller_epoch: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(DatabaseError::NetworkMissing)
}

fn create_node_invitation(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &CreateNodeInvitationRequest,
    controller_origin: &str,
) -> Result<CreateNodeInvitationResponse, DatabaseError> {
    let now = unix_timestamp()?;
    let expires_at = now
        .checked_add(i64::from(request.expires_in_seconds))
        .ok_or(DatabaseError::TimestampOverflow)?;
    let invitation_id = NodeInvitationId::new();
    let mut secret_bytes = [0_u8; INVITATION_SECRET_BYTES];
    OsRng.fill_bytes(&mut secret_bytes);
    let invitation_secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let secret_verifier = Sha256::digest(invitation_secret.as_bytes());
    let fingerprint = identity.fingerprint();
    let network = load_network(connection)?;

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO node_invitations(
            invitation_id, network_id, purpose, intended_display_name, secret_verifier,
            controller_origin, controller_fingerprint, expires_at, created_at
         ) VALUES (?1, ?2, 'node-enrollment', ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            invitation_id.to_string(),
            network.network_id,
            request.display_name,
            secret_verifier.as_slice(),
            controller_origin,
            fingerprint.as_str(),
            expires_at,
            now,
        ],
    )?;
    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "admin",
        None,
        "node-invitation.created",
        "node-invitation",
        Some(&invitation_id.to_string()),
        "success",
        &serde_json::json!({
            "expiresAt": timestamp(expires_at)?.to_string(),
            "intendedDisplayName": request.display_name,
            "purpose": "node-enrollment"
        }),
        now,
    )?;
    transaction.commit()?;

    Ok(CreateNodeInvitationResponse {
        invitation_id,
        purpose: PairingPurpose::NodeEnrollment,
        expires_at: timestamp(expires_at)?,
        invitation_secret: Secret::new(invitation_secret),
        controller_origin: controller_origin.to_string(),
        controller_fingerprint: fingerprint,
    })
}

fn enroll_node(
    connection: &mut Connection,
    identity: &ControllerIdentity,
    request: &EnrollNodeRequest,
) -> Result<NodeEnrollmentResult, DatabaseError> {
    let now = unix_timestamp()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let network = load_network(&transaction)?;
    let validated =
        match validate_enrollment_attempt(&transaction, &network, identity, request, now) {
            Ok(validated) => validated,
            Err(error) if error.is_audited_enrollment_rejection() => {
                transaction.commit()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
    if let ValidatedEnrollment::Existing {
        created,
        request_transcript,
    } = validated
    {
        let response =
            build_enrollment_response(&network, identity, &created, &request_transcript)?;
        transaction.commit()?;
        return Ok(NodeEnrollmentResult {
            response,
            created: false,
        });
    }
    let ValidatedEnrollment::New {
        invitation_id,
        request_transcript,
    } = validated
    else {
        unreachable!("existing enrollment returned above");
    };
    let created = insert_node_records(&transaction, &network.network_id, request, now)?;
    consume_invitation(&transaction, &invitation_id, created.node_id, now)?;
    let response = build_enrollment_response(&network, identity, &created, &request_transcript)?;

    insert_audit_event(
        &transaction,
        Some(&network.network_id),
        "node",
        Some(&created.node_id.to_string()),
        "node.enrolled",
        "node",
        Some(&created.node_id.to_string()),
        "success",
        &serde_json::json!({
            "agentVersion": request.agent_version,
            "invitationId": invitation_id,
            "platform": request.platform,
            "providerConsentPolicyVersion": request.provider_consent.policy_version
        }),
        now,
    )?;
    transaction.commit()?;
    Ok(NodeEnrollmentResult {
        response,
        created: true,
    })
}

enum ValidatedEnrollment {
    New {
        invitation_id: String,
        request_transcript: Vec<u8>,
    },
    Existing {
        created: CreatedNode,
        request_transcript: Vec<u8>,
    },
}

fn validate_enrollment_attempt(
    transaction: &rusqlite::Transaction<'_>,
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    request: &EnrollNodeRequest,
    now: i64,
) -> Result<ValidatedEnrollment, DatabaseError> {
    let verifier = Sha256::digest(request.invitation_secret.expose_secret().as_bytes());
    let invitation = load_invitation(transaction, verifier.as_slice())?;
    let Some(invitation) = invitation else {
        // Unknown random secrets are intentionally not persisted, avoiding an
        // unauthenticated audit-log amplification path.
        return Err(DatabaseError::InvitationInvalid);
    };

    validate_invitation_state(transaction, network, identity, &invitation, now)?;
    let invitation_id = invitation
        .invitation_id
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let fingerprint = invitation
        .controller_fingerprint
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)?;
    let context = EnrollmentInvitation {
        invitation_id,
        purpose: PairingPurpose::NodeEnrollment,
        expires_at: timestamp(invitation.expires_at)?,
        controller_origin: &invitation.controller_origin,
        controller_fingerprint: &fingerprint,
    };
    let request_transcript = enrollment_request_transcript(&context, request)?;
    if verify_enrollment_proof(request, &request_transcript).is_err() {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "signature-invalid",
            DatabaseError::InvalidEnrollmentProof,
            now,
        );
    }
    if let Some(consumed_node_id) = invitation.consumed_node_id.as_deref() {
        if let Some(created) =
            load_existing_enrollment(transaction, &network.network_id, consumed_node_id, request)?
        {
            return Ok(ValidatedEnrollment::Existing {
                created,
                request_transcript,
            });
        }
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            "invitation-consumed",
            DatabaseError::InvitationConsumed,
            now,
        );
    }
    Ok(ValidatedEnrollment::New {
        invitation_id: invitation.invitation_id,
        request_transcript,
    })
}

fn validate_invitation_state(
    transaction: &rusqlite::Transaction<'_>,
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    invitation: &InvitationRecord,
    now: i64,
) -> Result<(), DatabaseError> {
    let rejection = if invitation.cancelled_at.is_some() {
        Some(("invitation-cancelled", DatabaseError::InvitationCancelled))
    } else if invitation.consumed_node_id.is_none() && invitation.expires_at <= now {
        Some(("invitation-expired", DatabaseError::InvitationExpired))
    } else if invitation.controller_fingerprint != identity.fingerprint().as_str() {
        Some((
            "controller-identity-mismatch",
            DatabaseError::ControllerIdentityMismatch,
        ))
    } else {
        None
    };
    if let Some((reason, error)) = rejection {
        return reject_enrollment(
            transaction,
            &network.network_id,
            Some(&invitation.invitation_id),
            reason,
            error,
            now,
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CreatedNode {
    node_id: NodeId,
    key_id: NodeKeyId,
    credential_expires_at: i64,
}

fn load_existing_enrollment(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    node_id: &str,
    request: &EnrollNodeRequest,
) -> Result<Option<CreatedNode>, DatabaseError> {
    transaction
        .query_row(
            "SELECT n.node_id, c.node_credential_id, c.expires_at
             FROM nodes AS n
             JOIN node_auth_credentials AS c
               ON c.network_id = n.network_id AND c.node_id = n.node_id
             WHERE n.network_id = ?1 AND n.node_id = ?2
               AND n.identity_public_key = ?3 AND n.encryption_public_key = ?4
               AND c.identity_public_key = ?3 AND c.revoked_at IS NULL
             ORDER BY c.created_at DESC LIMIT 1",
            params![
                network_id,
                node_id,
                request.identity_public_key.as_str(),
                request.encryption_public_key.as_str(),
            ],
            |row| {
                let node_id = row.get::<_, String>(0)?;
                let key_id = row.get::<_, String>(1)?;
                Ok((node_id, key_id, row.get::<_, i64>(2)?))
            },
        )
        .optional()?
        .map(|(node_id, key_id, credential_expires_at)| {
            Ok(CreatedNode {
                node_id: node_id
                    .parse()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                key_id: key_id
                    .parse()
                    .map_err(|_| DatabaseError::StoredProtocolValue)?,
                credential_expires_at,
            })
        })
        .transpose()
}

fn insert_node_records(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    request: &EnrollNodeRequest,
    now: i64,
) -> Result<CreatedNode, DatabaseError> {
    let created = CreatedNode {
        node_id: NodeId::new(),
        key_id: NodeKeyId::new(),
        credential_expires_at: OffsetDateTime::from_unix_timestamp(now)?
            .checked_add(Duration::days(NODE_CREDENTIAL_LIFETIME_DAYS))
            .ok_or(DatabaseError::TimestampOverflow)?
            .unix_timestamp(),
    };
    transaction.execute(
        "INSERT INTO nodes(
            node_id, network_id, display_name, status, agent_version, platform,
            capabilities_json, identity_public_key, encryption_public_key,
            consent_policy_version, consent_host_owner, consent_exit_ip,
            consent_accepted_at, created_at, updated_at
         ) VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, ?10, ?11, ?11)",
        params![
            created.node_id.to_string(),
            network_id,
            request.display_name,
            request.agent_version,
            request.platform,
            serde_json::to_string(&request.capabilities)?,
            request.identity_public_key.as_str(),
            request.encryption_public_key.as_str(),
            request.provider_consent.policy_version,
            request
                .provider_consent
                .accepted_at
                .as_datetime()
                .unix_timestamp(),
            now,
        ],
    )?;
    transaction.execute(
        "INSERT INTO node_auth_credentials(
            network_id, node_credential_id, node_id, identity_public_key,
            auth_mode, not_before, expires_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, 'signedRequest', ?5, ?6, ?5)",
        params![
            network_id,
            created.key_id.to_string(),
            created.node_id.to_string(),
            request.identity_public_key.as_str(),
            now,
            created.credential_expires_at,
        ],
    )?;
    Ok(created)
}

fn consume_invitation(
    transaction: &rusqlite::Transaction<'_>,
    invitation_id: &str,
    node_id: NodeId,
    now: i64,
) -> Result<(), DatabaseError> {
    let consumed = transaction.execute(
        "UPDATE node_invitations SET consumed_at = ?1, consumed_node_id = ?2
         WHERE invitation_id = ?3 AND consumed_at IS NULL AND cancelled_at IS NULL",
        params![now, node_id.to_string(), invitation_id],
    )?;
    if consumed == 1 {
        Ok(())
    } else {
        Err(DatabaseError::InvitationConsumed)
    }
}

fn build_enrollment_response(
    network: &NetworkRecord,
    identity: &ControllerIdentity,
    created: &CreatedNode,
    request_transcript: &[u8],
) -> Result<EnrollNodeResponse, DatabaseError> {
    let mut response = EnrollNodeResponse {
        network_id: network
            .network_id
            .parse::<NetworkId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        node_id: created.node_id,
        controller_instance_id: network
            .controller_epoch
            .parse::<ControllerInstanceId>()
            .map_err(|_| DatabaseError::StoredProtocolValue)?,
        credential: NodeCredential {
            key_id: created.key_id,
            mode: NodeAuthenticationMode::SignedRequest,
            expires_at: timestamp(created.credential_expires_at)?,
            client_certificate_pem: None,
        },
        desired_state_signing_public_key: identity.public_key(),
        controller_nonce: random_nonce()?,
        proof: zero_signature()?,
    };
    let transcript = enrollment_response_transcript(request_transcript, &response)?;
    response.proof = identity.sign(&transcript)?;
    Ok(response)
}

fn reject_enrollment<T>(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    invitation_id: Option<&str>,
    reason: &str,
    error: DatabaseError,
    now: i64,
) -> Result<T, DatabaseError> {
    insert_enrollment_rejection(transaction, network_id, invitation_id, reason, now)?;
    Err(error)
}

struct InvitationRecord {
    invitation_id: String,
    controller_origin: String,
    controller_fingerprint: String,
    expires_at: i64,
    consumed_node_id: Option<String>,
    cancelled_at: Option<i64>,
}

fn load_invitation(
    transaction: &rusqlite::Transaction<'_>,
    verifier: &[u8],
) -> Result<Option<InvitationRecord>, DatabaseError> {
    transaction
        .query_row(
            "SELECT invitation_id, controller_origin, controller_fingerprint,
                    expires_at, consumed_node_id, cancelled_at
             FROM node_invitations
             WHERE secret_verifier = ?1 AND purpose = 'node-enrollment'",
            [verifier],
            |row| {
                Ok(InvitationRecord {
                    invitation_id: row.get(0)?,
                    controller_origin: row.get(1)?,
                    controller_fingerprint: row.get(2)?,
                    expires_at: row.get(3)?,
                    consumed_node_id: row.get(4)?,
                    cancelled_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(DatabaseError::from)
}

fn insert_enrollment_rejection(
    transaction: &rusqlite::Transaction<'_>,
    network_id: &str,
    invitation_id: Option<&str>,
    reason: &str,
    now: i64,
) -> Result<(), DatabaseError> {
    insert_audit_event(
        transaction,
        Some(network_id),
        "anonymous-node",
        None,
        "node.enrollment-rejected",
        "node-invitation",
        invitation_id,
        "rejected",
        &serde_json::json!({ "reason": reason }),
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_audit_event(
    transaction: &rusqlite::Transaction<'_>,
    network_id: Option<&str>,
    actor_type: &str,
    actor_id: Option<&str>,
    event_type: &str,
    target_type: &str,
    target_id: Option<&str>,
    outcome: &str,
    details: &serde_json::Value,
    now: i64,
) -> Result<(), DatabaseError> {
    transaction.execute(
        "INSERT INTO audit_events(
            network_id, actor_type, actor_id, event_type, target_type,
            target_id, outcome, details_json, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            network_id,
            actor_type,
            actor_id,
            event_type,
            target_type,
            target_id,
            outcome,
            serde_json::to_string(details)?,
            now,
        ],
    )?;
    Ok(())
}

fn random_nonce() -> Result<control_protocol::crypto::Nonce, DatabaseError> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD
        .encode(bytes)
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)
}

fn zero_signature() -> Result<control_protocol::crypto::Ed25519Signature, DatabaseError> {
    URL_SAFE_NO_PAD
        .encode([0_u8; 64])
        .parse()
        .map_err(|_| DatabaseError::StoredProtocolValue)
}

fn timestamp(value: i64) -> Result<Timestamp, DatabaseError> {
    Ok(Timestamp::from_datetime(
        OffsetDateTime::from_unix_timestamp(value)?,
    ))
}

fn verify_database(connection: &Connection) -> Result<(), DatabaseError> {
    let foreign_key_violation = connection.prepare("PRAGMA foreign_key_check")?.exists([])?;
    if foreign_key_violation {
        return Err(DatabaseError::ForeignKeyViolation);
    }

    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(DatabaseError::IntegrityCheckFailed(quick_check));
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64, DatabaseError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(DatabaseError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| DatabaseError::TimestampOverflow)
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidConfiguration(#[from] ConfigError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Validation(#[from] ProtocolValidationError),
    #[error(transparent)]
    EnrollmentCrypto(#[from] EnrollmentCryptoError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    TimestampComponent(#[from] time::error::ComponentRange),
    #[error("database is already owned by another process: {lock_path}")]
    DatabaseLocked {
        lock_path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("database belongs to another application (expected {expected}, found {actual})")]
    WrongApplicationId { expected: i64, actual: i64 },
    #[error("database schema {actual} is newer than supported schema {supported}")]
    SchemaTooNew { supported: i64, actual: i64 },
    #[error(
        "schema_migrations version {source_version} does not match PRAGMA user_version {user_version}"
    )]
    MigrationMirrorMismatch {
        source_version: i64,
        user_version: i64,
    },
    #[error("migration {version} checksum or name does not match this binary")]
    MigrationChecksumMismatch { version: i64 },
    #[error("migration history has a gap before version {version}")]
    MigrationGap { version: i64 },
    #[error("expected one network but found {0}")]
    MultipleNetworks(i64),
    #[error("the bootstrapped network is missing")]
    NetworkMissing,
    #[error("database foreign key validation failed")]
    ForeignKeyViolation,
    #[error("database quick_check failed: {0}")]
    IntegrityCheckFailed(String),
    #[error("database worker failed")]
    Worker(#[source] tokio::task::JoinError),
    #[error("database mutex was poisoned")]
    LockPoisoned,
    #[error("system clock is before the Unix epoch")]
    Clock(#[source] std::time::SystemTimeError),
    #[error("current timestamp does not fit in SQLite INTEGER")]
    TimestampOverflow,
    #[error("the invitation is invalid")]
    InvitationInvalid,
    #[error("the invitation has expired")]
    InvitationExpired,
    #[error("the invitation was already consumed")]
    InvitationConsumed,
    #[error("the invitation was cancelled")]
    InvitationCancelled,
    #[error("the node enrollment proof is invalid")]
    InvalidEnrollmentProof,
    #[error("the controller identity no longer matches the invitation")]
    ControllerIdentityMismatch,
    #[error("a stored protocol value is invalid")]
    StoredProtocolValue,
}

impl DatabaseError {
    fn is_audited_enrollment_rejection(&self) -> bool {
        matches!(
            self,
            Self::InvitationExpired
                | Self::InvitationConsumed
                | Self::InvitationCancelled
                | Self::InvalidEnrollmentProof
                | Self::ControllerIdentityMismatch
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        lock_path, migration_checksum, Database, DatabaseError, MIGRATIONS, SCHEMA_VERSION,
    };
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn database_path(temp: &TempDir) -> std::path::PathBuf {
        temp.path().join("control.sqlite3")
    }

    #[test]
    fn applies_required_pragmas_and_records_authoritative_migration() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        let guard = database.inner.lock().unwrap();
        let connection = &guard.connection;

        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            connection
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            5000
        );
        assert_eq!(
            connection
                .query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("PRAGMA secure_delete", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            SCHEMA_VERSION
        );

        for migration in MIGRATIONS {
            let stored: (String, String) = connection
                .query_row(
                    "SELECT name, checksum FROM schema_migrations WHERE version = ?1",
                    [migration.version],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(stored.0, migration.name);
            assert_eq!(stored.1, migration_checksum(migration));
        }
    }

    #[test]
    fn bootstrap_is_idempotent_and_preserves_network_identity() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let first = Database::open(&path, "Friends").unwrap();
        let first_network = {
            let guard = first.inner.lock().unwrap();
            super::load_network(&guard.connection).unwrap()
        };
        drop(first);

        let reopened = Database::open(&path, "A changed startup label").unwrap();
        let reopened_network = {
            let guard = reopened.inner.lock().unwrap();
            super::load_network(&guard.connection).unwrap()
        };

        assert_eq!(reopened_network, first_network);
        assert_eq!(reopened_network.display_name, "Friends");
    }

    #[test]
    fn rejects_a_modified_migration_history() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        drop(database);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 2",
                [],
            )
            .unwrap();
        drop(connection);

        let error = Database::open(&path, "Friends")
            .err()
            .expect("tampered migration must fail");
        assert!(matches!(
            error,
            DatabaseError::MigrationChecksumMismatch { version: 2 }
        ));
    }

    #[test]
    fn rejects_migration_gaps_and_future_schemas() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let database = Database::open(&path, "Friends").unwrap();
        drop(database);

        let connection = Connection::open(&path).unwrap();
        connection
            .execute("DELETE FROM schema_migrations WHERE version = 1", [])
            .unwrap();
        drop(connection);
        let gap = Database::open(&path, "Friends")
            .err()
            .expect("migration gap must fail");
        assert!(matches!(gap, DatabaseError::MigrationGap { version: 1 }));

        let second_temp = TempDir::new().unwrap();
        let second_path = database_path(&second_temp);
        let database = Database::open(&second_path, "Friends").unwrap();
        drop(database);
        let connection = Connection::open(&second_path).unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        drop(connection);
        let future = Database::open(&second_path, "Friends")
            .err()
            .expect("future schema must fail");
        assert!(matches!(
            future,
            DatabaseError::SchemaTooNew {
                supported: SCHEMA_VERSION,
                actual: 99
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn database_and_lock_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let _database = Database::open(&path, "Friends").unwrap();

        for secure_path in [&path, &lock_path(&path)] {
            let mode = std::fs::metadata(secure_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} was not owner-only", secure_path.display());
        }
    }

    #[test]
    fn enforces_single_process_ownership() {
        let temp = TempDir::new().unwrap();
        let path = database_path(&temp);
        let _first = Database::open(&path, "Friends").unwrap();

        let error = Database::open(&path, "Friends")
            .err()
            .expect("a second owner must fail");
        assert!(matches!(error, DatabaseError::DatabaseLocked { .. }));
    }
}
