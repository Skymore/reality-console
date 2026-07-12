use control_server::db::SCHEMA_VERSION;
use control_server::Database;
use serde_json::Value;
use std::process::{Command, Output};
use tempfile::TempDir;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_control-server"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn backup_verify_and_restore_dry_run_use_redacted_cli_contracts() {
    let temp = TempDir::new().unwrap();
    let database = temp.path().join("control.sqlite3");
    drop(Database::open(&database, "CLI Backup Test").unwrap());
    let backup = temp.path().join("backup");
    let restore = temp.path().join("restore");

    let create = run(&[
        "backup",
        "create",
        "--database",
        database.to_str().unwrap(),
        "--destination",
        backup.to_str().unwrap(),
        "--external-encryption-contract",
        "test-encrypted-destination",
    ]);
    assert!(create.status.success(), "{:?}", create.stderr);
    let create_json: Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(create_json["databaseSchemaVersion"], SCHEMA_VERSION);
    assert!(!String::from_utf8_lossy(&create.stdout).contains("controller-ed25519"));

    let verify = run(&["backup", "verify", "--backup", backup.to_str().unwrap()]);
    assert!(verify.status.success(), "{:?}", verify.stderr);
    let verify_json: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_json["manifestSha256"], create_json["manifestSha256"]);

    let dry_run = run(&[
        "restore",
        "--backup",
        backup.to_str().unwrap(),
        "--destination",
        restore.to_str().unwrap(),
        "--current-database",
        database.to_str().unwrap(),
        "--recovery-mode",
        "--dry-run",
    ]);
    assert!(dry_run.status.success(), "{:?}", dry_run.stderr);
    let restore_json: Value = serde_json::from_slice(&dry_run.stdout).unwrap();
    assert_eq!(restore_json["verified"], true);
    assert_eq!(restore_json["restored"], false);
    assert!(!restore.exists());
}

#[test]
fn restore_cli_fails_closed_without_explicit_recovery_mode() {
    let output = run(&[
        "restore",
        "--backup",
        "redacted-backup",
        "--destination",
        "redacted-destination",
        "--no-local-history",
    ]);
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--recovery-mode"));
    assert!(!error.contains("controller-ed25519"));
}
