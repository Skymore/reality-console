use crate::{
    build_status, configure_controller, load_registration, migrate, open_database,
    parse_controller, persist_verified_registration, DataDirLock, HostStatus, Identity,
};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519Signature, Nonce, Sha256Digest};
use control_protocol::enrollment::{
    enrollment_request_transcript, enrollment_response_transcript, EnrollmentInvitation,
};
use control_protocol::error::ErrorEnvelope;
use control_protocol::node::{
    CreateNodeInvitationResponse, EnrollNodeRequest, EnrollNodeResponse, NodeAuthenticationMode,
    NodeCapability, PairingPurpose, ProviderConsent,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use reqwest::{redirect::Policy, StatusCode};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::str::FromStr as _;
use std::time::Duration;
use time::OffsetDateTime;

const MAX_INVITATION_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const INVITATION_SECRET_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const PROVIDER_CONSENT_POLICY_VERSION: &str = "2026-07-11";

/// Enrolls this installation with the controller from a one-time invitation.
///
/// The invitation secret and private identity material are never persisted in
/// `SQLite` or included in command output. Registration metadata is committed
/// only after the pinned controller response has been verified.
///
/// # Errors
///
/// Returns an error for missing consent, malformed or expired invitations,
/// transport failures, invalid controller proofs, or conflicting local state.
pub async fn join(
    data_dir: &Path,
    invitation_file: &Path,
    display_name: &str,
    accept_host_owner: bool,
    accept_exit_ip: bool,
) -> Result<HostStatus> {
    if !accept_host_owner || !accept_exit_ip {
        bail!(
            "joining requires both --accept-host-owner and --accept-exit-ip after reviewing the provider disclosure"
        );
    }

    let invitation = read_invitation(invitation_file)?;
    validate_invitation(&invitation)?;
    let controller = parse_controller(&invitation.controller_origin)?;

    let _lock = DataDirLock::acquire(data_dir, true)?;
    let mut connection = open_database(data_dir, true)?;
    migrate(&mut connection)?;
    configure_controller(&connection, &controller)?;
    let identity = Identity::load_or_create(data_dir)?;

    if let Some(existing) = load_registration(&connection)? {
        if existing.invitation_id != invitation.invitation_id.to_string() {
            bail!("node host is already enrolled with a different invitation");
        }
        if existing.controller_fingerprint != invitation.controller_fingerprint.as_str() {
            bail!("stored controller fingerprint does not match the invitation");
        }
    }

    let (request, request_transcript) =
        build_enrollment_request(&invitation, display_name, &identity)?;
    let response = post_enrollment(&controller, &request).await?;
    verify_controller_response(&invitation, &request_transcript, &response)?;
    persist_verified_registration(
        &mut connection,
        invitation.invitation_id,
        invitation.controller_fingerprint.as_str(),
        &response,
    )?;
    build_status(&connection, controller, &identity)
}

fn read_invitation(path: &Path) -> Result<CreateNodeInvitationResponse> {
    let path_metadata =
        std::fs::symlink_metadata(path).context("failed to inspect invitation path")?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("invitation path must be a regular non-symlink file");
    }
    ensure_invitation_owner_only(&path_metadata)?;
    let mut file = File::open(path).context("failed to open invitation file")?;
    let metadata = file
        .metadata()
        .context("failed to inspect invitation file")?;
    if metadata.len() == 0 || metadata.len() > MAX_INVITATION_BYTES {
        bail!("invitation file must contain between 1 byte and 64 KiB");
    }
    let capacity =
        usize::try_from(metadata.len()).context("invitation file size is unsupported")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_INVITATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read invitation file")?;
    if bytes.len() as u64 > MAX_INVITATION_BYTES {
        bail!("invitation file exceeds 64 KiB");
    }
    serde_json::from_slice(&bytes).context("invitation file is not valid invitation JSON")
}

fn validate_invitation(invitation: &CreateNodeInvitationResponse) -> Result<()> {
    if invitation.purpose != PairingPurpose::NodeEnrollment {
        bail!("invitation is not intended for node enrollment");
    }
    parse_controller(&invitation.controller_origin)?;
    let secret = URL_SAFE_NO_PAD
        .decode(invitation.invitation_secret.expose_secret())
        .context("invitation secret is malformed")?;
    if secret.len() != INVITATION_SECRET_BYTES {
        bail!("invitation secret is malformed");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_invitation_owner_only(metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("invitation file must not be accessible by group or other users");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_invitation_owner_only(_metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

fn build_enrollment_request(
    invitation: &CreateNodeInvitationResponse,
    display_name: &str,
    identity: &Identity,
) -> Result<(EnrollNodeRequest, Vec<u8>)> {
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_str(&URL_SAFE_NO_PAD.encode(nonce_bytes))
        .context("failed to encode enrollment nonce")?;
    let mut request = EnrollNodeRequest {
        invitation_secret: invitation.invitation_secret.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: platform_name(),
        display_name: display_name.to_string(),
        capabilities: vec![NodeCapability::Xray],
        identity_public_key: identity.ed25519_public()?,
        encryption_public_key: identity.x25519_public()?,
        nonce,
        proof: zero_signature()?,
        provider_consent: ProviderConsent {
            policy_version: PROVIDER_CONSENT_POLICY_VERSION.to_string(),
            host_owner_consented: true,
            exit_ip_disclosure_accepted: true,
            accepted_at: control_protocol::id::Timestamp::from_datetime(OffsetDateTime::now_utc()),
        },
    };
    request
        .validate()
        .context("node enrollment fields are invalid")?;
    let context = EnrollmentInvitation {
        invitation_id: invitation.invitation_id,
        purpose: invitation.purpose,
        expires_at: invitation.expires_at,
        controller_origin: &invitation.controller_origin,
        controller_fingerprint: &invitation.controller_fingerprint,
    };
    let transcript = enrollment_request_transcript(&context, &request)
        .context("failed to encode enrollment request proof")?;
    request.proof = identity.sign(&transcript)?;
    Ok((request, transcript))
}

async fn post_enrollment(
    controller: &url::Url,
    request: &EnrollNodeRequest,
) -> Result<EnrollNodeResponse> {
    let endpoint = controller
        .join("/v1/nodes/enroll")
        .context("failed to construct enrollment endpoint")?;
    let client = control_http_client().context("failed to initialize enrollment HTTP client")?;
    let response = client
        .post(endpoint)
        .json(request)
        .send()
        .await
        .context("controller enrollment request failed")?;
    let status = response.status();
    let bytes = read_bounded_response(response).await?;
    if !status.is_success() {
        return Err(controller_error(status, &bytes));
    }
    if status != StatusCode::OK && status != StatusCode::CREATED {
        bail!("controller returned unexpected success status {status}");
    }
    serde_json::from_slice(&bytes).context("controller returned an invalid enrollment response")
}

pub(crate) fn control_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::none())
        .user_agent(concat!("node-host/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to initialize controller HTTP client")
}

pub(crate) async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("controller response exceeds 64 KiB");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read controller response")?
    {
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .context("controller response size overflow")?;
        if next_length > MAX_RESPONSE_BYTES {
            bail!("controller response exceeds 64 KiB");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn controller_error(status: StatusCode, bytes: &[u8]) -> anyhow::Error {
    if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(bytes) {
        anyhow::anyhow!(
            "controller rejected enrollment with {} (request {})",
            envelope.error.code,
            envelope.error.request_id
        )
    } else {
        anyhow::anyhow!("controller rejected enrollment with HTTP {status}")
    }
}

fn verify_controller_response(
    invitation: &CreateNodeInvitationResponse,
    request_transcript: &[u8],
    response: &EnrollNodeResponse,
) -> Result<()> {
    let public_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(response.desired_state_signing_public_key.as_str())
        .context("controller signing public key is malformed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller signing public key is malformed"))?;
    let fingerprint = public_key_fingerprint(public_bytes)?;
    if fingerprint != invitation.controller_fingerprint {
        bail!("controller signing key fingerprint does not match the invitation");
    }
    if response.credential.expires_at.as_datetime() <= OffsetDateTime::now_utc() {
        bail!("controller issued an expired node credential");
    }
    if response.credential.mode != NodeAuthenticationMode::SignedRequest {
        bail!("controller issued an unsupported node authentication mode");
    }

    let response_transcript = enrollment_response_transcript(request_transcript, response)
        .context("failed to encode controller enrollment proof")?;
    let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(response.proof.as_str())
        .context("controller enrollment proof is malformed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("controller enrollment proof is malformed"))?;
    let key = VerifyingKey::from_bytes(&public_bytes)
        .context("controller signing public key is invalid")?;
    key.verify_strict(
        &response_transcript,
        &Signature::from_bytes(&signature_bytes),
    )
    .context("controller enrollment proof is invalid")
}

fn public_key_fingerprint(public_key: [u8; 32]) -> Result<Sha256Digest> {
    let digest = Sha256::digest(public_key);
    format!("sha256:{digest:x}")
        .parse()
        .context("failed to encode controller fingerprint")
}

fn zero_signature() -> Result<Ed25519Signature> {
    URL_SAFE_NO_PAD
        .encode([0_u8; 64])
        .parse()
        .context("failed to initialize enrollment proof")
}

fn platform_name() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-arm64".to_string(),
        ("macos", "x86_64") => "macos-x86_64".to_string(),
        ("windows", "aarch64") => "windows-arm64".to_string(),
        ("windows", "x86_64") => "windows-x86_64".to_string(),
        ("linux", "aarch64") => "linux-arm64".to_string(),
        ("linux", "x86_64") => "linux-x86_64".to_string(),
        (os, architecture) => format!("{os}-{architecture}"),
    }
}
