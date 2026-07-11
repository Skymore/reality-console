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
use tokio::time::{sleep, Instant};
use uuid::Uuid;
use xray_runtime::{
    probe_version, start_managed, test_config, BinaryValidationError, ConfigValidationError,
    ExecutionLimits, RealityPrivateKey, RealityTarget, RuntimeError, ServerName, Sha256Digest,
    ShortId, UserEmail, VerifiedXrayBinary, VerifiedXrayConfig, VlessRealityConfigBuilder,
    VlessUser, XrayBinarySpec, XrayConfigSpec,
};

struct FakeExecutable {
    directory: TempDir,
    path: PathBuf,
    digest: Sha256Digest,
}

struct ConfigFile {
    directory: TempDir,
    path: PathBuf,
    digest: Sha256Digest,
}

impl ConfigFile {
    fn new(contents: &[u8]) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("xray-config.json");
        fs::write(&path, contents).expect("write Xray config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make config owner-only");
        Self {
            directory,
            path,
            digest: digest(contents),
        }
    }

    fn verify(&self) -> VerifiedXrayConfig {
        XrayConfigSpec::new(&self.path, self.digest)
            .expect("absolute path")
            .verify()
            .expect("verified Xray config")
    }
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

fn rendered_empty_access_config() -> xray_runtime::RenderedXrayConfig {
    VlessRealityConfigBuilder::new(
        "127.0.0.1".parse().expect("valid IP"),
        18443,
        RealityTarget::new("www.example.com", 443).expect("valid target"),
        RealityPrivateKey::parse(&URL_SAFE_NO_PAD.encode([8_u8; 32])).expect("valid private key"),
    )
    .expect("valid builder")
    .server_name(ServerName::parse("www.example.com").expect("valid server name"))
    .short_id(ShortId::parse("1122334455667788").expect("valid short ID"))
    .build()
    .expect("empty access config")
}

fn short_limits() -> ExecutionLimits {
    ExecutionLimits::new(Duration::from_secs(2), 1024).expect("valid limits")
}

async fn read_created_file(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match fs::read_to_string(path) {
            Ok(contents) => return contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(Instant::now() < deadline, "timed out waiting for fake Xray");
                sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("failed to read fake Xray report: {error}"),
        }
    }
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

#[tokio::test]
async fn managed_child_receives_exact_arguments() {
    let fake = FakeExecutable::new(
        r#"if [ "$#" -ne 3 ] || [ "$1" != "run" ] || [ "$2" != "-config" ]; then
  exit 51
fi
printf '%s\n' "$#" "$1" "$2" "$3" > "$0.argv"
exec /bin/sleep 30"#,
    );
    let report_path = fake.path.with_extension("argv");
    let config = ConfigFile::new(b"{\"log\":{}}\n");
    let binary = fake.verify();
    let verified_config = config.verify();

    let mut child = start_managed(&binary, &verified_config)
        .await
        .expect("managed child starts");
    assert_ne!(child.pid(), 0);
    let report = read_created_file(&report_path).await;
    let arguments: Vec<_> = report.lines().collect();
    assert_eq!(
        arguments,
        ["3", "run", "-config", config.path.to_str().unwrap()]
    );

    child
        .kill_and_wait()
        .await
        .expect("managed child is killed and reaped");
}

#[tokio::test]
async fn managed_start_rejects_config_mutation_before_spawn() {
    const MUTATED_CONFIG: &[u8] = b"{\"mutated\":true}\n";

    let fake = FakeExecutable::new(
        r#"printf 'spawned\n' > "$0.spawned"
exec /bin/sleep 30"#,
    );
    let spawn_marker = fake.path.with_extension("spawned");
    let config = ConfigFile::new(b"{\"original\":true}\n");
    let verified_config = config.verify();
    fs::write(&config.path, MUTATED_CONFIG).expect("mutate verified config");
    fs::set_permissions(&config.path, fs::Permissions::from_mode(0o600))
        .expect("retain owner-only permissions");

    let error = start_managed(&fake.verify(), &verified_config)
        .await
        .expect_err("mutated config must fail revalidation");
    let message = error.to_string();
    assert!(matches!(
        error,
        RuntimeError::ConfigValidation(ConfigValidationError::ChecksumMismatch)
    ));
    assert!(!message.contains(String::from_utf8_lossy(MUTATED_CONFIG).as_ref()));
    assert!(!message.contains(config.path.to_string_lossy().as_ref()));
    assert!(!spawn_marker.exists());
}

#[test]
fn config_spec_rejects_unsafe_files() {
    let expected = digest(b"{}\n");
    let relative_error =
        XrayConfigSpec::new("relative/config.json", expected).expect_err("relative path must fail");
    assert!(matches!(
        relative_error,
        ConfigValidationError::PathMustBeAbsolute
    ));

    for mode in [0o400, 0o640, 0o700] {
        let wrong_mode = ConfigFile::new(b"{}\n");
        fs::set_permissions(&wrong_mode.path, fs::Permissions::from_mode(mode))
            .expect("set non-0600 config mode");
        let error = XrayConfigSpec::new(&wrong_mode.path, wrong_mode.digest)
            .expect("absolute path")
            .verify()
            .expect_err("non-0600 config must fail");
        assert!(matches!(error, ConfigValidationError::UnsafePermissions));
    }

    let target = ConfigFile::new(b"{}\n");
    let link = target.directory.path().join("config-link.json");
    symlink(&target.path, &link).expect("create config symlink");
    let error = XrayConfigSpec::new(link, target.digest)
        .expect("absolute path")
        .verify()
        .expect_err("config symlink must fail");
    assert!(matches!(error, ConfigValidationError::SymlinkNotAllowed));

    let error = XrayConfigSpec::new(target.directory.path(), target.digest)
        .expect("absolute path")
        .verify()
        .expect_err("config directory must fail");
    assert!(matches!(error, ConfigValidationError::NotRegularFile));

    let mismatch = ConfigFile::new(b"{}\n");
    let error = XrayConfigSpec::new(&mismatch.path, digest(b"different\n"))
        .expect("absolute path")
        .verify()
        .expect_err("config checksum mismatch must fail");
    assert!(matches!(error, ConfigValidationError::ChecksumMismatch));

    let directory = tempfile::tempdir().expect("temporary directory");
    for (name, length) in [("empty", 0), ("oversized", 2 * 1024 * 1024 + 1)] {
        let path = directory.path().join(name);
        let file = fs::File::create(&path).expect("create bounded test config");
        file.set_len(length).expect("set sparse config length");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make config owner-only");
        let error = XrayConfigSpec::new(&path, expected)
            .expect("absolute path")
            .verify()
            .expect_err("invalid config size must fail before hashing");
        assert!(matches!(error, ConfigValidationError::InvalidFileSize));
    }
}

#[tokio::test]
async fn managed_child_can_be_forcefully_killed_and_reaped() {
    let fake = FakeExecutable::new("exec /bin/sleep 30");
    let config = ConfigFile::new(b"{}\n");
    let binary = fake.verify();
    let verified_config = config.verify();
    let mut child = start_managed(&binary, &verified_config)
        .await
        .expect("managed child starts");

    assert!(child.try_wait().expect("poll managed child").is_none());
    let status = child
        .kill_and_wait()
        .await
        .expect("forcefully kill and reap managed child");
    assert!(!status.success());
    assert!(child
        .try_wait()
        .expect("poll reaped managed child")
        .is_some());
}

#[tokio::test]
#[ignore = "requires XRAY_RUNTIME_REAL_BINARY pointing to a trusted current Xray executable"]
async fn current_xray_accepts_generated_user_and_empty_access_configs() {
    let path = std::env::var_os("XRAY_RUNTIME_REAL_BINARY")
        .map(PathBuf::from)
        .expect("XRAY_RUNTIME_REAL_BINARY");
    let contents = fs::read(&path).expect("read real Xray binary");
    let binary = XrayBinarySpec::new(path, digest(&contents))
        .expect("absolute path")
        .verify()
        .expect("verified real Xray binary");
    for config in [rendered_config(), rendered_empty_access_config()] {
        test_config(&binary, &config, ExecutionLimits::default())
            .await
            .expect("current Xray must accept generated config");
    }
}

#[test]
fn binary_spec_requires_an_absolute_path() {
    let digest = Sha256Digest::from_hex(&"00".repeat(32)).expect("valid digest shape");
    let error = XrayBinarySpec::new(Path::new("relative/xray"), digest)
        .expect_err("relative path must fail");
    assert!(matches!(error, BinaryValidationError::PathMustBeAbsolute));
}
