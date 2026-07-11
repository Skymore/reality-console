mod core;
mod error;
mod profile;
mod state;

use core::config::{build_xray_config, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use core::invite::{parse_invitation, InvitationPreview};
use error::ClientError;
use profile::{ProfileRepository, StoredProfile};
use state::{ClientRuntime, ClientState};
use tauri::{Manager, State};

async fn run_blocking<T, F>(task: F) -> Result<T, ClientError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ClientError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|_| {
            ClientError::internal(
                "background_task_failed",
                "The background operation could not be completed.",
            )
        })?
}

#[tauri::command]
fn client_get_state(runtime: State<'_, ClientRuntime>) -> Result<ClientState, ClientError> {
    runtime
        .snapshot()
        .map_err(|code| ClientError::internal(code, "The client state is temporarily unavailable."))
}

#[tauri::command]
fn client_preview_invitation(invitation: String) -> Result<InvitationPreview, ClientError> {
    parse_invitation(&invitation).map(|profile| {
        // Build once during validation so an accepted invitation is guaranteed to map to the
        // runtime configuration shape without exposing that configuration to the renderer.
        let _config = build_xray_config(&profile, DEFAULT_SOCKS_PORT, DEFAULT_HTTP_PORT);
        InvitationPreview::from(&profile)
    })
}

#[tauri::command]
async fn client_list_profiles(
    profiles: State<'_, ProfileRepository>,
) -> Result<Vec<StoredProfile>, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.list()).await
}

#[tauri::command]
async fn client_import_profile(
    invitation: String,
    name: Option<String>,
    profiles: State<'_, ProfileRepository>,
) -> Result<StoredProfile, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.import(&invitation, name.as_deref())).await
}

#[tauri::command]
async fn client_rename_profile(
    profile_id: String,
    name: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<StoredProfile, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.rename(&profile_id, &name)).await
}

#[tauri::command]
async fn client_delete_profile(
    profile_id: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<(), ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || profiles.delete(&profile_id)).await
}

#[tauri::command]
async fn client_preview_profile(
    profile_id: String,
    profiles: State<'_, ProfileRepository>,
) -> Result<InvitationPreview, ClientError> {
    let profiles = profiles.inner().clone();
    run_blocking(move || {
        profiles
            .load_connection(&profile_id)
            .map(|profile| InvitationPreview::from(&profile))
    })
    .await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let profiles = ProfileRepository::native(app_data_dir)
                .map_err(|error| std::io::Error::other(error.message))?;
            app.manage(profiles);
            Ok(())
        })
        .manage(ClientRuntime::default())
        .invoke_handler(tauri::generate_handler![
            client_get_state,
            client_preview_invitation,
            client_list_profiles,
            client_import_profile,
            client_rename_profile,
            client_delete_profile,
            client_preview_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running Reality Client");
}
