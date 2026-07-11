use crate::enrollment::{
    join_invitation, parse_invitation_json, read_invitation, require_provider_consent,
};
use crate::{configure_xray, initialize, HostStatus};
use anyhow::{Context as _, Result};
use control_protocol::node::CreateNodeInvitationResponse;
use std::path::{Path, PathBuf};

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
}

impl BootstrapRequest {
    /// Builds a setup request from invitation JSON held in memory by a desktop UI.
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
    ) -> Result<Self> {
        Ok(Self {
            invitation: parse_invitation_json(invitation_json)?,
            display_name: display_name.into(),
            xray_binary_path,
            xray_sha256: xray_sha256.into(),
            accept_host_owner,
            accept_exit_ip,
        })
    }

    /// Builds an installer integration request from an owner-only invitation file.
    ///
    /// Desktop applications should prefer [`Self::from_invitation_json`] so the
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
    ) -> Result<Self> {
        Ok(Self {
            invitation: read_invitation(invitation_file)?,
            display_name: display_name.into(),
            xray_binary_path,
            xray_sha256: xray_sha256.into(),
            accept_host_owner,
            accept_exit_ip,
        })
    }
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
