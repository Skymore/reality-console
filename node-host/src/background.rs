use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

/// Stable internal launchd label for the preview Node Host user service.
pub const USER_SERVICE_LABEL: &str = "com.realityconsole.node-host";

/// Installer-owned input for registering the Node Host background process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserServiceInstallRequest {
    /// Explicit path to the signed or installer-bundled Node Host executable.
    pub agent_binary_path: PathBuf,
}

impl UserServiceInstallRequest {
    /// Creates a user-service installation request.
    #[must_use]
    pub fn new(agent_binary_path: PathBuf) -> Self {
        Self { agent_binary_path }
    }
}

/// Safe launch-service registration state for a local owner UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundServiceStatus {
    /// OS service mechanism used by this implementation.
    pub platform: &'static str,
    /// Stable internal service-manager label.
    pub label: &'static str,
    /// Whether the expected service definition exists as a regular file.
    pub installed: bool,
    /// Whether the OS service manager currently has the definition loaded.
    pub loaded: bool,
}

/// Registers and starts the current user's macOS Node Host `LaunchAgent`.
///
/// This preview integration is deliberately user-scoped and requires an
/// interactive login session. Production unattended packages use the same
/// agent `run` boundary behind a signed system `LaunchDaemon`.
///
/// # Errors
///
/// Returns an error when the platform is unsupported, local state is not
/// enrolled, paths are unsafe, registration is concurrent, or launchd rejects
/// the bounded fixed command.
pub async fn install_user_service(
    data_dir: &std::path::Path,
    request: &UserServiceInstallRequest,
) -> Result<BackgroundServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        crate::background_macos::install(data_dir, request).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (data_dir, request);
        anyhow::bail!("the preview user background service is supported only on macOS");
    }
}

/// Reads the current user's macOS Node Host `LaunchAgent` registration state.
///
/// # Errors
///
/// Returns an error when the platform is unsupported, the user environment is
/// unsafe, the service definition is a symlink, or launchd cannot be queried.
pub async fn user_service_status() -> Result<BackgroundServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        crate::background_macos::status().await
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("the preview user background service is supported only on macOS");
    }
}

/// Stops and unregisters the current user's macOS Node Host `LaunchAgent`.
///
/// Node identity, enrollment state, and logs are retained. A later local
/// unpair operation owns destructive credential removal.
///
/// # Errors
///
/// Returns an error when the platform is unsupported, registration is
/// concurrent, launchd cannot stop the service, or the service definition
/// cannot be safely removed.
pub async fn remove_user_service() -> Result<BackgroundServiceStatus> {
    #[cfg(target_os = "macos")]
    {
        crate::background_macos::remove().await
    }
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("the preview user background service is supported only on macOS");
    }
}
