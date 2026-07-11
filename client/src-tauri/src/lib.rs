mod core;
mod error;
mod state;

use core::config::{build_xray_config, DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT};
use core::invite::{parse_invitation, InvitationPreview};
use error::ClientError;
use state::{ClientRuntime, ClientState};
use tauri::State;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(ClientRuntime::default())
        .invoke_handler(tauri::generate_handler![
            client_get_state,
            client_preview_invitation
        ])
        .run(tauri::generate_context!())
        .expect("error while running Reality Client");
}
