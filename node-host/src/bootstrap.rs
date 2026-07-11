use crate::enrollment::{
    join_invitation, parse_invitation_json, read_invitation, require_provider_consent,
};
use crate::{
    configure_xray, initialize, install_user_service, mapping::configure_bootstrap_policy,
    parse_controller, BackgroundServiceStatus, HostStatus, UserServiceInstallRequest,
};
use anyhow::{Context as _, Result};
use control_protocol::crypto::Sha256Digest;
use control_protocol::id::Timestamp;
use control_protocol::node::{
    decode_node_setup_code, CreateNodeInvitationResponse, NodeSetupInvitation,
    NODE_SETUP_CODE_PREFIX,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use url::Url;

/// Complete installer-owned input for one friend-facing Node Host setup.
///
/// Invitation material is parsed before this value is created and is never
/// exposed through formatting or command-line arguments. The Xray path and
/// digest are supplied by the signed installer rather than entered by a host.
pub struct BootstrapRequest {
    invitation: CreateNodeInvitationResponse,
    display_name: String,
    xray_binary_path: PathBuf,
    xray_sha256: String,
    accept_host_owner: bool,
    accept_exit_ip: bool,
    accept_router_mapping: bool,
}

/// Result of the friend-facing setup path after background registration.
#[derive(Debug)]
pub struct BootstrapServiceOutcome {
    /// Enrolled Node Host state.
    pub host: HostStatus,
    /// Native service-manager registration state.
    pub service: BackgroundServiceStatus,
}

/// Secret-free setup information suitable for the provider confirmation UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSetupPreview {
    /// Operator-selected node name.
    pub display_name: String,
    /// Pinned Control Service origin.
    pub controller_origin: Url,
    /// Pinned controller identity fingerprint for an optional advanced check.
    pub controller_fingerprint: Sha256Digest,
    /// Absolute one-time-code expiry.
    pub expires_at: Timestamp,
}

/// Decodes a setup code without initializing local state or contacting Control.
///
/// The returned preview deliberately omits the invitation ID and bearer
/// secret. It retains the controller fingerprint for an optional advanced
/// identity check. The caller should retain the original code only in memory
/// until bootstrap completes.
///
/// # Errors
///
/// Returns an error when the setup code or controller origin is invalid.
pub fn inspect_setup_code(setup_code: &str) -> Result<NodeSetupPreview> {
    let setup = decode_setup_input(setup_code)?;
    let controller_origin = parse_controller(&setup.invitation.controller_origin)
        .context("Node Host setup code contains an invalid controller origin")?;
    Ok(NodeSetupPreview {
        display_name: setup.display_name,
        controller_origin,
        controller_fingerprint: setup.invitation.controller_fingerprint,
        expires_at: setup.invitation.expires_at,
    })
}

impl BootstrapRequest {
    /// Builds a one-action setup request from a pasted or QR-scanned code.
    ///
    /// The operator-selected node name and controller identity come from the
    /// code. Xray path and digest still come from the signed installer.
    ///
    /// # Errors
    ///
    /// Returns an error when the setup code is malformed or unsupported.
    pub fn from_setup_code(
        setup_code: &str,
        xray_binary_path: PathBuf,
        xray_sha256: impl Into<String>,
        accept_host_owner: bool,
        accept_exit_ip: bool,
        accept_router_mapping: bool,
    ) -> Result<Self> {
        let NodeSetupInvitation {
            display_name,
            invitation,
        } = decode_setup_input(setup_code)?;
        Ok(Self {
            invitation,
            display_name,
            xray_binary_path,
            xray_sha256: xray_sha256.into(),
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        })
    }

    /// Builds a legacy integration request from raw invitation JSON.
    ///
    /// Desktop applications should use [`Self::from_setup_code`] so the
    /// operator-bound display name and link-origin checks cannot be bypassed.
    ///
    /// # Errors
    ///
    /// Returns an error when the invitation is malformed, oversized, has the
    /// wrong purpose, or contains an invalid controller origin or secret.
    pub fn from_invitation_json(
        invitation_json: &[u8],
        display_name: impl Into<String>,
        xray_binary_path: PathBuf,
        xray_sha256: impl Into<String>,
        accept_host_owner: bool,
        accept_exit_ip: bool,
        accept_router_mapping: bool,
    ) -> Result<Self> {
        Ok(Self {
            invitation: parse_invitation_json(invitation_json)?,
            display_name: display_name.into(),
            xray_binary_path,
            xray_sha256: xray_sha256.into(),
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        })
    }

    /// Builds an installer integration request from an owner-only invitation file.
    ///
    /// Desktop applications should prefer [`Self::from_setup_code`] so the
    /// one-time secret never needs a filesystem artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the invitation file is unsafe, malformed, or invalid.
    pub fn from_invitation_file(
        invitation_file: &Path,
        display_name: impl Into<String>,
        xray_binary_path: PathBuf,
        xray_sha256: impl Into<String>,
        accept_host_owner: bool,
        accept_exit_ip: bool,
        accept_router_mapping: bool,
    ) -> Result<Self> {
        Ok(Self {
            invitation: read_invitation(invitation_file)?,
            display_name: display_name.into(),
            xray_binary_path,
            xray_sha256: xray_sha256.into(),
            accept_host_owner,
            accept_exit_ip,
            accept_router_mapping,
        })
    }
}

fn decode_setup_input(value: &str) -> Result<NodeSetupInvitation> {
    let value = value.trim();
    if value.starts_with(NODE_SETUP_CODE_PREFIX) {
        return decode_node_setup_code(value).context("Node Host setup code is invalid");
    }
    let link = Url::parse(value).context("Node Host setup link is invalid")?;
    if link.path() != "/join/node"
        || link.query().is_some()
        || !link.username().is_empty()
        || link.password().is_some()
    {
        anyhow::bail!("Node Host setup link has an unsupported shape");
    }
    let setup_code = link
        .fragment()
        .context("Node Host setup link has no invitation fragment")?;
    let setup = decode_node_setup_code(setup_code).context("Node Host setup link is invalid")?;
    let link_origin = parse_controller(&link.origin().ascii_serialization())?;
    let invitation_origin = parse_controller(&setup.invitation.controller_origin)?;
    if link_origin != invitation_origin {
        anyhow::bail!("Node Host setup link controller does not match its invitation");
    }
    Ok(setup)
}

/// Performs idempotent local setup, bundled-Xray verification, and enrollment.
///
/// The bundled runtime is verified before the single-use invitation is sent to
/// the controller. A retry reuses the same local identity and the same verified
/// runtime, allowing a desktop UI to expose one safe `Try again` action.
///
/// # Errors
///
/// Returns a stage-specific error for missing provider consent, conflicting
/// local state, bundled runtime verification, or controller enrollment.
pub async fn bootstrap(data_dir: &Path, request: BootstrapRequest) -> Result<HostStatus> {
    require_provider_consent(request.accept_host_owner, request.accept_exit_ip)
        .context("Node Host bootstrap requires explicit provider consent")?;
    initialize(data_dir, &request.invitation.controller_origin)
        .context("Node Host bootstrap could not initialize local state")?;
    configure_xray(
        data_dir,
        &request.xray_binary_path,
        &request.xray_sha256,
        false,
    )
    .await
    .context("Node Host bootstrap could not verify the bundled Xray runtime")?;
    configure_bootstrap_policy(data_dir, request.accept_router_mapping)
        .context("Node Host bootstrap could not persist the router-mapping preference")?;
    join_invitation(
        data_dir,
        request.invitation,
        &request.display_name,
        request.accept_host_owner,
        request.accept_exit_ip,
    )
    .await
    .context("Node Host bootstrap could not complete controller enrollment")
}

/// Completes bootstrap and then registers the enrolled host in the native
/// user-scoped background service.
///
/// Enrollment commits before service registration. If launchd registration
/// fails, retrying this complete operation is safe: bootstrap reuses the same
/// local identity and controller registration, while service installation
/// independently restores any previous service definition on failure.
///
/// # Errors
///
/// Returns a stage-specific bootstrap error or a background-service error. A
/// service-stage error does not roll back a valid controller enrollment.
pub async fn bootstrap_and_install_user_service(
    data_dir: &Path,
    bootstrap_request: BootstrapRequest,
    service_request: &UserServiceInstallRequest,
) -> Result<BootstrapServiceOutcome> {
    let host = bootstrap(data_dir, bootstrap_request).await?;
    let service = install_user_service(data_dir, service_request)
        .await
        .context("Node Host bootstrap enrolled successfully but background startup failed")?;
    Ok(BootstrapServiceOutcome { host, service })
}
