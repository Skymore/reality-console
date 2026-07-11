#![cfg(unix)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use node_host::{configure_xray, initialize, status};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

struct FakeXray {
    _directory: tempfile::TempDir,
    path: PathBuf,
    digest: String,
    invocation_marker: PathBuf,
}

impl FakeXray {
    fn new(version: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("xray");
        let invocation_marker = directory.path().join("invoked");
        let script = format!(
            "#!/bin/sh\n: > \"{}\"\nif [ \"$#\" -ne 1 ] || [ \"$1\" != \"version\" ]; then exit 41; fi\nprintf '{version}\\nsecondary line\\n'\n",
            invocation_marker.display()
        );
        fs::write(&path, script.as_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            _directory: directory,
            path,
            digest: sha256_hex(script.as_bytes()),
            invocation_marker,
        }
    }
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

#[tokio::test]
async fn configures_a_pinned_runtime_and_keeps_reality_identity_out_of_sqlite() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    initialize(&data_dir, "https://controller.example").unwrap();
    let fake = FakeXray::new("Xray 25.7.1");

    let configured = configure_xray(&data_dir, &fake.path, &fake.digest, false)
        .await
        .unwrap();
    assert_eq!(configured.schema_version, 10);
    assert!(configured.xray_configured);
    assert_eq!(
        configured.xray_binary_path.as_deref(),
        Some(fake.path.as_path())
    );
    assert_eq!(
        configured.xray_expected_sha256.as_deref(),
        Some(fake.digest.as_str())
    );
    assert_eq!(configured.xray_version.as_deref(), Some("Xray 25.7.1"));
    assert!(configured.reality_public_key.is_some());
    assert_eq!(configured.reality_short_id.as_deref().unwrap().len(), 16);

    let seed_path = data_dir.join("reality.x25519.seed");
    let seed = fs::read(&seed_path).unwrap();
    assert_eq!(seed.len(), 32);
    assert_eq!(
        fs::metadata(&seed_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let database = fs::read(data_dir.join("node-host.sqlite3")).unwrap();
    assert!(!contains_bytes(&database, &seed));
    assert!(!contains_bytes(
        &database,
        URL_SAFE_NO_PAD.encode(&seed).as_bytes()
    ));

    let repeated = configure_xray(&data_dir, &fake.path, &fake.digest, false)
        .await
        .unwrap();
    assert_eq!(repeated.reality_public_key, configured.reality_public_key);
    assert_eq!(repeated.reality_short_id, configured.reality_short_id);
    assert_eq!(
        status(&data_dir).unwrap().xray_version.as_deref(),
        Some("Xray 25.7.1")
    );
}

#[tokio::test]
async fn replacement_is_explicit_and_preserves_the_reality_identity() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    initialize(&data_dir, "https://controller.example").unwrap();
    let first = FakeXray::new("Xray 25.7.1");
    let second = FakeXray::new("Xray 25.8.0");
    let initial = configure_xray(&data_dir, &first.path, &first.digest, false)
        .await
        .unwrap();

    let error = configure_xray(&data_dir, &second.path, &second.digest, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("--replace"));
    assert!(!second.invocation_marker.exists());
    assert_eq!(
        status(&data_dir).unwrap().xray_binary_path.as_deref(),
        Some(first.path.as_path())
    );

    let replaced = configure_xray(&data_dir, &second.path, &second.digest, true)
        .await
        .unwrap();
    assert_eq!(
        replaced.xray_binary_path.as_deref(),
        Some(second.path.as_path())
    );
    assert_eq!(replaced.xray_version.as_deref(), Some("Xray 25.8.0"));
    assert_eq!(replaced.reality_public_key, initial.reality_public_key);
    assert_eq!(replaced.reality_short_id, initial.reality_short_id);
}

#[tokio::test]
async fn failed_binary_verification_does_not_create_reality_key_material() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("state");
    initialize(&data_dir, "https://controller.example").unwrap();
    let fake = FakeXray::new("Xray 25.7.1");

    let error = configure_xray(&data_dir, &fake.path, &"00".repeat(32), false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("verification failed"));
    assert!(!fake.invocation_marker.exists());
    assert!(!data_dir.join("reality.x25519.seed").exists());
    assert!(!status(&data_dir).unwrap().xray_configured);
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
