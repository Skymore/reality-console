#![cfg(unix)]

use std::{
    fmt::Write as _,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use uuid::Uuid;
use xray_runtime::{
    probe_version, test_config, BinaryValidationError, ExecutionLimits, RealityPrivateKey,
    RealityTarget, RuntimeError, ServerName, Sha256Digest, ShortId, UserEmail, VerifiedXrayBinary,
    VlessRealityConfigBuilder, VlessUser, XrayBinarySpec,
};

struct FakeExecutable {
    directory: TempDir,
    path: PathBuf,
    digest: Sha256Digest,
}

impl FakeExecutable {
    fn new(script_body: &str) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("fake-xray");
        let script = format!("#!/bin/sh\n{script_body}\n");
        fs::write(&path, script.as_bytes()).expect("write fake executable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make fake executable executable");
        let digest = digest(script.as_bytes());
        Self {
            directory,
            path,
            digest,
        }
    }

    fn verify(&self) -> VerifiedXrayBinary {
        XrayBinarySpec::new(&self.path, self.digest)
            .expect("absolute path")
            .verify()
            .expect("verified fake executable")
    }
}

fn digest(contents: &[u8]) -> Sha256Digest {
    let bytes: [u8; 32] = Sha256::digest(contents).into();
    let hex = bytes
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to String cannot fail");
            hex
        });
    Sha256Digest::from_hex(&hex).expect("valid digest")
}

fn rendered_config() -> xray_runtime::RenderedXrayConfig {
    let private_key =
        RealityPrivateKey::parse(&URL_SAFE_NO_PAD.encode([9_u8; 32])).expect("valid private key");
    let user = VlessUser::new(
        Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("valid UUID"),
        UserEmail::parse("friend@example.com").expect("valid email"),
        true,
    )
    .expect("valid user");
    VlessRealityConfigBuilder::new(
        "0.0.0.0".parse().expect("valid IP"),
        443,
        RealityTarget::new("www.example.com", 443).expect("valid target"),
        private_key,
    )
    .expect("valid builder")
    .server_name(ServerName::parse("www.example.com").expect("valid server name"))
    .short_id(ShortId::parse("aabbccdd").expect("valid short ID"))
    .user(user)
    .build()
    .expect("valid rendered config")
}

fn short_limits() -> ExecutionLimits {
    ExecutionLimits::new(Duration::from_secs(1), 1024).expect("valid limits")
}

#[test]
fn verifies_regular_executable_and_rejects_checksum_mismatch() {
    let fake = FakeExecutable::new("printf 'Xray 1.0.0\\n'");
    fake.verify();

    let wrong = Sha256Digest::from_hex(&"00".repeat(32)).expect("valid digest shape");
    let error = XrayBinarySpec::new(&fake.path, wrong)
        .expect("absolute path")
        .verify()
        .expect_err("checksum mismatch");
    assert!(matches!(error, BinaryValidationError::ChecksumMismatch));
}

#[test]
fn rejects_non_executable_and_symbolic_link_paths() {
    let fake = FakeExecutable::new("printf 'Xray 1.0.0\\n'");
    fs::set_permissions(&fake.path, fs::Permissions::from_mode(0o600))
        .expect("remove executable bit");
    let error = XrayBinarySpec::new(&fake.path, fake.digest)
        .expect("absolute path")
        .verify()
        .expect_err("non-executable must fail");
    assert!(matches!(error, BinaryValidationError::NotExecutable));

    fs::set_permissions(&fake.path, fs::Permissions::from_mode(0o700))
        .expect("restore executable bit");
    let link = fake.path.with_file_name("fake-xray-link");
    symlink(&fake.path, &link).expect("create symlink");
    let error = XrayBinarySpec::new(link, fake.digest)
        .expect("absolute path")
        .verify()
        .expect_err("symlink must fail");
    assert!(matches!(error, BinaryValidationError::SymlinkNotAllowed));

    let error = XrayBinarySpec::new(fake.directory.path(), fake.digest)
        .expect("absolute path")
        .verify()
        .expect_err("directory must fail");
    assert!(matches!(error, BinaryValidationError::NotRegularFile));
}

#[test]
fn rejects_writable_empty_and_oversized_executables_before_hashing() {
    let writable = FakeExecutable::new("printf 'Xray 1.0.0\\n'");
    fs::set_permissions(&writable.path, fs::Permissions::from_mode(0o722))
        .expect("make fake executable world-writable");
    let error = XrayBinarySpec::new(&writable.path, writable.digest)
        .expect("absolute path")
        .verify()
        .expect_err("unsafe permissions must fail");
    assert!(matches!(error, BinaryValidationError::UnsafePermissions));

    let directory = tempfile::tempdir().expect("temporary directory");
    for (name, length) in [("empty", 0), ("oversized", 256 * 1024 * 1024 + 1)] {
        let path = directory.path().join(name);
        let file = fs::File::create(&path).expect("create bounded test file");
        file.set_len(length).expect("set sparse test file length");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("make test file executable");
        let error = XrayBinarySpec::new(&path, Sha256Digest::from_hex(&"00".repeat(32)).unwrap())
            .expect("absolute path")
            .verify()
            .expect_err("invalid binary size must fail before hashing");
        assert!(matches!(error, BinaryValidationError::InvalidFileSize));
    }
}

#[tokio::test]
async fn probes_version_with_explicit_arguments() {
    let fake = FakeExecutable::new(
        r#"if [ "$#" -ne 1 ] || [ "$1" != "version" ]; then
  exit 41
fi
printf 'Xray 25.7.1\n'"#,
    );
    let result = probe_version(&fake.verify(), short_limits())
        .await
        .expect("version probe succeeds");
    assert_eq!(result.stdout(), "Xray 25.7.1");
    assert_eq!(result.stderr_bytes(), 0);
}

#[tokio::test]
async fn runs_config_test_with_private_tempfile_arguments() {
    let fake = FakeExecutable::new(
        r#"if [ "$#" -ne 4 ] || [ "$1" != "run" ] || [ "$2" != "-test" ] || [ "$3" != "-config" ]; then
  exit 42
fi
if [ ! -f "$4" ]; then
  exit 43
fi
mode=$(/bin/ls -l "$4")
case "$mode" in
  -rw-------*) ;;
  *) exit 44 ;;
esac
printf 'configuration OK\n'"#,
    );
    let report = test_config(&fake.verify(), &rendered_config(), short_limits())
        .await
        .expect("config test succeeds");
    assert!(report.stdout_bytes() > 0);
    assert_eq!(report.stderr_bytes(), 0);
}

#[tokio::test]
async fn terminates_a_timed_out_process() {
    let fake = FakeExecutable::new("/bin/sleep 2");
    let limits = ExecutionLimits::new(Duration::from_millis(40), 1024).expect("valid limits");
    let error = probe_version(&fake.verify(), limits)
        .await
        .expect_err("probe must time out");
    assert!(matches!(error, RuntimeError::TimedOut { .. }));
}

#[tokio::test]
async fn rejects_output_over_the_bound() {
    let fake = FakeExecutable::new(
        r#"i=0
while [ "$i" -lt 300 ]; do
  printf 'xxxxxxxxxxxxxxxx'
  i=$((i + 1))
done"#,
    );
    let limits = ExecutionLimits::new(Duration::from_secs(1), 128).expect("valid limits");
    let error = probe_version(&fake.verify(), limits)
        .await
        .expect_err("output must be bounded");
    assert!(matches!(
        error,
        RuntimeError::OutputLimitExceeded {
            stream: "stdout",
            limit: 128,
            ..
        }
    ));
}

#[tokio::test]
async fn non_zero_errors_do_not_expose_process_output_or_config() {
    const LEAK_MARKER: &str = "PRIVATE_KEY_AND_CONFIG_LEAK_MARKER";
    let fake = FakeExecutable::new(&format!(
        "printf '{LEAK_MARKER}'\nprintf '{LEAK_MARKER}' >&2\nexit 7"
    ));
    let config = rendered_config();
    let private_key = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let error = test_config(&fake.verify(), &config, short_limits())
        .await
        .expect_err("non-zero process must fail");
    let message = error.to_string();
    assert!(!message.contains(LEAK_MARKER));
    assert!(!message.contains(&private_key));
    assert!(!message.contains(config.expose_json()));
    assert!(matches!(
        error,
        RuntimeError::NonZeroExit {
            exit_code: Some(7),
            ..
        }
    ));
}

#[tokio::test]
async fn runtime_revalidates_checksum_before_each_spawn() {
    let fake = FakeExecutable::new("printf 'Xray 1.0.0\\n'");
    let verified = fake.verify();
    fs::write(&fake.path, "#!/bin/sh\nprintf 'mutated\\n'\n").expect("mutate fake binary");
    fs::set_permissions(&fake.path, fs::Permissions::from_mode(0o700))
        .expect("keep executable bit");

    let error = probe_version(&verified, short_limits())
        .await
        .expect_err("mutated binary must fail revalidation");
    assert!(matches!(
        error,
        RuntimeError::BinaryValidation(BinaryValidationError::ChecksumMismatch)
    ));
}

#[test]
fn binary_spec_requires_an_absolute_path() {
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("valid digest shape");
    let error = XrayBinarySpec::new(Path::new("relative/xray"), digest)
        .expect_err("relative path must fail");
    assert!(matches!(error, BinaryValidationError::PathMustBeAbsolute));
}
