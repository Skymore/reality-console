use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use release_manifest::{
    release_signing_transcript, rollback_signing_transcript, Architecture, Platform, Product,
    ReleaseArtifact, ReleaseManifest, ReleaseTrustStore, RollbackAuthorization,
    SignedReleaseManifest, SignedRollbackAuthorization, UpdatePolicy,
    RELEASE_MANIFEST_SCHEMA_VERSION, ROLLBACK_AUTHORIZATION_SCHEMA_VERSION,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use uuid::Uuid;

type Error = Box<dyn std::error::Error>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestInput {
    release_id: Uuid,
    source_commit: String,
    issued_at: i64,
    release_notes_url: Option<String>,
    artifacts: Vec<ArtifactInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ArtifactInput {
    product: Product,
    platform: Platform,
    architecture: Architecture,
    version: Version,
    path: PathBuf,
    sbom_path: PathBuf,
    minimum_configuration_schema: u16,
    maximum_configuration_schema: u16,
    xray_version: Option<Version>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackInput {
    authorization_id: Uuid,
    product: Product,
    platform: Platform,
    architecture: Architecture,
    from_version: Version,
    to_version: Version,
    artifact_sha256: String,
    reason_code: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustConfig {
    schema_version: u16,
    production_ready: bool,
    release_keys: Vec<TrustKey>,
    rollback_keys: Vec<TrustKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustKey {
    key_id: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseEvidence<'a> {
    schema_version: u16,
    release_id: Uuid,
    source_commit: &'a str,
    issued_at: i64,
    signature_status: &'static str,
    release_key_id: &'a str,
    manifest_sha256: String,
    artifacts: &'a [ReleaseArtifact],
}

fn sha256_file(path: &Path) -> Result<(u64, String), Error> {
    let mut source = File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count)?)
            .ok_or("artifact size overflow")?;
        digest.update(&buffer[..count]);
    }
    Ok((size, format!("{:x}", digest.finalize())))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    fs::write(&temporary, encoded)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn signing_key(variable: &str) -> Result<Option<SigningKey>, Error> {
    let Ok(encoded) = env::var(variable) else {
        return Ok(None);
    };
    if encoded.is_empty() {
        return Ok(None);
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "signing key must contain 32 bytes")?;
    Ok(Some(SigningKey::from_bytes(&bytes)))
}

fn trust_store(config: &TrustConfig) -> Result<ReleaseTrustStore, Error> {
    if config.schema_version != 1
        || config.release_keys.is_empty()
        || config.rollback_keys.is_empty()
    {
        return Err("release trust configuration is incomplete".into());
    }
    let mut store = ReleaseTrustStore::new();
    for key in &config.release_keys {
        store.add_release_key(&key.key_id, &key.public_key)?;
    }
    for key in &config.rollback_keys {
        store.add_rollback_key(&key.key_id, &key.public_key)?;
    }
    Ok(store)
}

fn artifact_input<'a>(
    input: &'a ManifestInput,
    artifact: &ReleaseArtifact,
) -> Result<&'a ArtifactInput, Error> {
    input
        .artifacts
        .iter()
        .find(|candidate| {
            candidate.product == artifact.product
                && candidate.platform == artifact.platform
                && candidate.architecture == artifact.architecture
        })
        .ok_or_else(|| "manifest artifact has no byte source".into())
}

fn verify_signed(
    signed: &SignedReleaseManifest,
    input: &ManifestInput,
    trust: &TrustConfig,
) -> Result<(), Error> {
    let store = trust_store(trust)?;
    for artifact in &signed.manifest.artifacts {
        let source = artifact_input(input, artifact)?;
        let verified = store.verify_update(
            signed,
            &UpdatePolicy {
                product: artifact.product,
                platform: artifact.platform,
                architecture: artifact.architecture,
                current_version: artifact.version.clone(),
                minimum_allowed_version: artifact.version.clone(),
                required_configuration_schema: artifact.minimum_configuration_schema,
                now: signed.manifest.issued_at,
            },
            None,
        )?;
        release_manifest::verify_artifact(File::open(&source.path)?, &verified.artifact)?;
    }
    Ok(())
}

fn generate_manifest(args: &[String]) -> Result<(), Error> {
    if args.len() != 6 {
        return Err("usage: generate INPUT MANIFEST EVIDENCE KEY_ID TRUST".into());
    }
    let require_signing = env::var("REQUIRE_SIGNING").as_deref() == Ok("1");
    if require_signing {
        let _ = fs::remove_file(&args[2]);
        let _ = fs::remove_file(&args[3]);
    }
    let input: ManifestInput = read_json(Path::new(&args[1]))?;
    let trust: TrustConfig = read_json(Path::new(&args[5]))?;
    let mut artifacts = Vec::with_capacity(input.artifacts.len());
    for artifact in &input.artifacts {
        let (size_bytes, sha256) = sha256_file(&artifact.path)?;
        let (_, sbom_sha256) = sha256_file(&artifact.sbom_path)?;
        artifacts.push(ReleaseArtifact {
            product: artifact.product,
            platform: artifact.platform,
            architecture: artifact.architecture,
            version: artifact.version.clone(),
            size_bytes,
            sha256,
            sbom_sha256,
            minimum_configuration_schema: artifact.minimum_configuration_schema,
            maximum_configuration_schema: artifact.maximum_configuration_schema,
            xray_version: artifact.xray_version.clone(),
        });
    }
    artifacts.sort_by_key(|artifact| (artifact.product, artifact.platform, artifact.architecture));
    let manifest = ReleaseManifest {
        schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
        release_id: input.release_id,
        source_commit: input.source_commit.clone(),
        issued_at: input.issued_at,
        release_notes_url: input.release_notes_url.clone(),
        artifacts,
    };
    let key_id = &args[4];
    let transcript = release_signing_transcript(key_id, &manifest)?;
    let key = signing_key("RELEASE_SIGNING_PRIVATE_KEY")?;
    let signature_status = if key.is_some() {
        "signed"
    } else {
        "unsigned-validation"
    };
    if require_signing && key.is_none() {
        return Err("RELEASE_SIGNING_PRIVATE_KEY is required in release mode".into());
    }
    if require_signing && !trust.production_ready {
        return Err("pinned release trust is not marked production-ready".into());
    }
    if let Some(key) = key {
        let signed = SignedReleaseManifest {
            key_id: key_id.clone(),
            manifest: manifest.clone(),
            signature: URL_SAFE_NO_PAD.encode(key.sign(&transcript).to_bytes()),
        };
        verify_signed(&signed, &input, &trust)?;
        write_json(Path::new(&args[2]), &signed)?;
    } else {
        for artifact in &manifest.artifacts {
            let source = artifact_input(&input, artifact)?;
            release_manifest::verify_artifact(File::open(&source.path)?, artifact)?;
        }
        write_json(Path::new(&args[2]), &manifest)?;
    }
    let manifest_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&manifest)?));
    write_json(
        Path::new(&args[3]),
        &ReleaseEvidence {
            schema_version: manifest.schema_version,
            release_id: manifest.release_id,
            source_commit: &manifest.source_commit,
            issued_at: manifest.issued_at,
            signature_status,
            release_key_id: key_id,
            manifest_sha256,
            artifacts: &manifest.artifacts,
        },
    )
}

fn verify_manifest(args: &[String]) -> Result<(), Error> {
    if args.len() != 4 {
        return Err("usage: verify SIGNED_MANIFEST INPUT TRUST".into());
    }
    let signed: SignedReleaseManifest = read_json(Path::new(&args[1]))?;
    let input: ManifestInput = read_json(Path::new(&args[2]))?;
    let trust: TrustConfig = read_json(Path::new(&args[3]))?;
    verify_signed(&signed, &input, &trust)
}

fn authorize_rollback(args: &[String]) -> Result<(), Error> {
    if args.len() != 5 {
        return Err("usage: authorize-rollback INPUT OUTPUT KEY_ID TRUST".into());
    }
    let require_signing = env::var("REQUIRE_SIGNING").as_deref() == Ok("1");
    if require_signing {
        let _ = fs::remove_file(&args[2]);
    }
    let input: RollbackInput = read_json(Path::new(&args[1]))?;
    let trust: TrustConfig = read_json(Path::new(&args[4]))?;
    let _ = trust_store(&trust)?;
    let authorization = RollbackAuthorization {
        schema_version: ROLLBACK_AUTHORIZATION_SCHEMA_VERSION,
        authorization_id: input.authorization_id,
        product: input.product,
        platform: input.platform,
        architecture: input.architecture,
        from_version: input.from_version,
        to_version: input.to_version,
        artifact_sha256: input.artifact_sha256,
        reason_code: input.reason_code,
        issued_at: input.issued_at,
        expires_at: input.expires_at,
    };
    let key_id = &args[3];
    let transcript = rollback_signing_transcript(key_id, &authorization)?;
    let key = signing_key("ROLLBACK_SIGNING_PRIVATE_KEY")?;
    if require_signing && key.is_none() {
        return Err("ROLLBACK_SIGNING_PRIVATE_KEY is required for rollback authorization".into());
    }
    if require_signing && !trust.production_ready {
        return Err("pinned rollback trust is not marked production-ready".into());
    }
    if let Some(key) = key {
        let pinned = trust
            .rollback_keys
            .iter()
            .find(|candidate| candidate.key_id == *key_id)
            .ok_or("rollback signing key ID is not pinned")?;
        let derived = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
        if derived != pinned.public_key {
            return Err("rollback signing key does not match pinned public key".into());
        }
        write_json(
            Path::new(&args[2]),
            &SignedRollbackAuthorization {
                key_id: key_id.clone(),
                authorization,
                signature: URL_SAFE_NO_PAD.encode(key.sign(&transcript).to_bytes()),
            },
        )
    } else {
        write_json(Path::new(&args[2]), &authorization)
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("generate") => generate_manifest(&args),
        Some("verify") => verify_manifest(&args),
        Some("authorize-rollback") => authorize_rollback(&args),
        _ => Err("usage: release-manifest-tool generate|verify|authorize-rollback ...".into()),
    }
}
