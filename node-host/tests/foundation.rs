use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use fs2::FileExt as _;
use predicates::prelude::*;
use rusqlite::Connection;
use std::fs::{self, OpenOptions};

#[test]
fn restart_is_idempotent_and_status_is_safe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("state");

    let first = node_host::initialize(&data_dir, "https://controller.example")
        .expect("first initialization");
    let second = node_host::initialize(&data_dir, "https://controller.example")
        .expect("second initialization");
    assert_eq!(
        first.identity_public_key.as_str(),
        second.identity_public_key.as_str()
    );
    assert_eq!(
        first.encryption_public_key.as_str(),
        second.encryption_public_key.as_str()
    );

    let signing_seed = fs::read(data_dir.join("identity.ed25519.seed")).expect("signing seed");
    let encryption_seed = fs::read(data_dir.join("identity.x25519.seed")).expect("encryption seed");
    let database = fs::read(data_dir.join("node-host.sqlite3")).expect("database bytes");
    assert!(!contains_bytes(&database, &signing_seed));
    assert!(!contains_bytes(&database, &encryption_seed));
    Command::cargo_bin("node-host")
        .expect("binary")
        .args(["status", "--data-dir"])
        .arg(&data_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("initialized: yes"))
        .stdout(predicate::str::contains(
            "controller: https://controller.example/",
        ))
        .stdout(predicate::str::contains(URL_SAFE_NO_PAD.encode(&signing_seed)).not())
        .stdout(predicate::str::contains(URL_SAFE_NO_PAD.encode(&encryption_seed)).not());
}

#[test]
fn migrations_are_recorded_once_and_pragmas_are_enabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("state");
    node_host::initialize(&data_dir, "http://localhost:8080").expect("initialize");

    let connection = Connection::open(data_dir.join("node-host.sqlite3")).expect("open database");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("migration count");
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode pragma");
    let user_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user version pragma");
    let migration: (String, String, i64) = connection
        .query_row(
            "SELECT name, checksum, applied_at FROM schema_migrations WHERE version = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("migration metadata");
    assert_eq!(count, 5);
    assert_eq!(journal_mode, "wal");
    assert_eq!(user_version, 5);
    assert_eq!(migration.0, "node_host_foundation");
    assert_eq!(migration.1.len(), 64);
    assert!(migration.2 > 0);
}

#[test]
fn cli_exposes_single_cycle_sync_command() {
    Command::cargo_bin("node-host")
        .expect("binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sync-once"))
        .stdout(predicate::str::contains("configure-xray"))
        .stdout(predicate::str::contains("run"));
}

#[test]
fn controller_must_be_a_secure_origin() {
    let temp = tempfile::tempdir().expect("tempdir");

    assert!(node_host::initialize(&temp.path().join("path"), "https://example.test/api").is_err());
    assert!(node_host::initialize(&temp.path().join("query"), "https://example.test?q=1").is_err());
    assert!(node_host::initialize(&temp.path().join("http"), "http://example.test").is_err());
    node_host::initialize(&temp.path().join("loopback"), "http://127.0.0.1:8787")
        .expect("loopback HTTP is allowed for development");
}

#[test]
fn modified_migration_history_is_rejected_by_status() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("state");
    node_host::initialize(&data_dir, "https://controller.example").expect("initialize");
    let connection = Connection::open(data_dir.join("node-host.sqlite3")).expect("open database");
    connection
        .execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
            [],
        )
        .expect("tamper migration");
    drop(connection);

    assert!(node_host::status(&data_dir).is_err());
}

#[cfg(unix)]
#[test]
fn identity_seed_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("state");
    node_host::initialize(&data_dir, "https://controller.example").expect("initialize");

    for name in ["identity.ed25519.seed", "identity.x25519.seed"] {
        let mode = fs::metadata(data_dir.join(name))
            .expect("seed metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn initialization_requires_the_exclusive_data_directory_lock() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data_dir = temp.path().join("state");
    node_host::initialize(&data_dir, "https://controller.example").expect("initialize");

    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(data_dir.join("node-host.lock"))
        .expect("open lock");
    lock.try_lock_exclusive().expect("hold exclusive lock");
    let error = node_host::status(&data_dir).expect_err("status must reject a held lock");
    assert!(error.to_string().contains("already in use"));
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
