use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

const CONFIG_RELATIVE_PATH: &str =
    "Library/Application Support/Private Network/Control Service/control-service.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ControlConfig {
    bind_address: String,
    bootstrap_token: String,
    public_origin: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlSnapshot {
    installed: bool,
    healthy: bool,
    local_origin: Option<String>,
    public_origin: Option<String>,
    network: Option<Value>,
    nodes: Vec<Value>,
    accounts: Vec<Value>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAccountInput {
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountNodesInput {
    user_id: String,
    node_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatusInput {
    user_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectSetupInput {
    user_id: String,
    expires_in_seconds: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeSetupInput {
    display_name: String,
    listen_port: Option<u16>,
    public_port: Option<u16>,
    server_name: Option<String>,
    target: Option<String>,
    expires_in_seconds: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeActionInput {
    node_id: String,
    action: String,
}

struct ControlClient {
    client: Client,
    origin: String,
    token: String,
    public_origin: String,
}

impl ControlClient {
    fn load() -> Result<Self, String> {
        let path = config_path()?;
        ensure_private_config(&path)?;
        let contents = fs::read(&path)
            .map_err(|error| format!("Failed to read Control Service configuration: {error}"))?;
        let config: ControlConfig = serde_json::from_slice(&contents)
            .map_err(|error| format!("Failed to parse Control Service configuration: {error}"))?;
        let origin = loopback_origin(&config.bind_address)?;
        if config.bootstrap_token.len() < 32 {
            return Err("Control Service administrator credential is invalid.".to_string());
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|error| format!("Failed to initialize Control Service client: {error}"))?;
        Ok(Self {
            client,
            origin,
            token: config.bootstrap_token,
            public_origin: config.public_origin,
        })
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.origin, path))
            .bearer_auth(&self.token)
            .header("X-Request-ID", Uuid::new_v4().to_string())
    }

    fn get_json(&self, path: &str) -> Result<Value, String> {
        send_json(self.request(Method::GET, path))
    }

    fn mutate_json(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        idempotent: bool,
    ) -> Result<Value, String> {
        let mut request = self.request(method, path);
        if idempotent {
            request = request.header("Idempotency-Key", Uuid::new_v4().to_string());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        send_json(request)
    }
}

#[tauri::command]
pub async fn get_control_snapshot() -> Result<ControlSnapshot, String> {
    super::run_blocking(get_control_snapshot_sync).await
}

fn get_control_snapshot_sync() -> Result<ControlSnapshot, String> {
    let control = match ControlClient::load() {
        Ok(control) => control,
        Err(error) => {
            return Ok(ControlSnapshot {
                installed: false,
                healthy: false,
                local_origin: None,
                public_origin: None,
                network: None,
                nodes: Vec::new(),
                accounts: Vec::new(),
                error: Some(error),
            });
        }
    };

    let network = control.get_json("/v1/admin/network");
    let nodes = control.get_json("/v1/admin/nodes");
    let accounts = control.get_json("/v1/admin/accounts");
    let error = network
        .as_ref()
        .err()
        .or_else(|| nodes.as_ref().err())
        .or_else(|| accounts.as_ref().err())
        .cloned();

    Ok(ControlSnapshot {
        installed: true,
        healthy: error.is_none(),
        local_origin: Some(control.origin),
        public_origin: Some(control.public_origin),
        network: network.ok(),
        nodes: nodes
            .ok()
            .and_then(|value| value.get("nodes").and_then(Value::as_array).cloned())
            .unwrap_or_default(),
        accounts: accounts
            .ok()
            .and_then(|value| value.get("accounts").and_then(Value::as_array).cloned())
            .unwrap_or_default(),
        error,
    })
}

#[tauri::command]
pub async fn create_control_account(input: CreateAccountInput) -> Result<Value, String> {
    super::run_blocking(move || {
        let display_name = validate_label(&input.display_name, "Friend name")?;
        ControlClient::load()?.mutate_json(
            Method::POST,
            "/v1/admin/accounts",
            Some(json!({ "displayName": display_name })),
            true,
        )
    })
    .await
}

#[tauri::command]
pub async fn update_control_account_nodes(input: AccountNodesInput) -> Result<Value, String> {
    super::run_blocking(move || {
        validate_uuid(&input.user_id, "account")?;
        for node_id in &input.node_ids {
            validate_uuid(node_id, "node")?;
        }
        ControlClient::load()?.mutate_json(
            Method::PUT,
            &format!("/v1/admin/accounts/{}/nodes", input.user_id),
            Some(json!({ "nodeIds": input.node_ids })),
            false,
        )
    })
    .await
}

#[tauri::command]
pub async fn set_control_account_status(input: AccountStatusInput) -> Result<Value, String> {
    super::run_blocking(move || {
        validate_uuid(&input.user_id, "account")?;
        if !matches!(input.status.as_str(), "active" | "disabled" | "deleted") {
            return Err("Account status is invalid.".to_string());
        }
        ControlClient::load()?.mutate_json(
            Method::PUT,
            &format!("/v1/admin/accounts/{}/status", input.user_id),
            Some(json!({ "status": input.status })),
            false,
        )
    })
    .await
}

#[tauri::command]
pub async fn create_connect_setup(input: ConnectSetupInput) -> Result<Value, String> {
    super::run_blocking(move || {
        validate_uuid(&input.user_id, "account")?;
        let expires = input.expires_in_seconds.unwrap_or(900).clamp(300, 3600);
        ControlClient::load()?.mutate_json(
            Method::POST,
            &format!("/v1/admin/accounts/{}/device-activations", input.user_id),
            Some(json!({ "expiresInSeconds": expires })),
            true,
        )
    })
    .await
}

#[tauri::command]
pub async fn create_node_setup(input: NodeSetupInput) -> Result<Value, String> {
    super::run_blocking(move || {
        let display_name = validate_label(&input.display_name, "Node name")?;
        let listen_port = input.listen_port.unwrap_or(10443);
        let public_port = input.public_port.unwrap_or(443);
        let server_name = input
            .server_name
            .unwrap_or_else(|| "dl.google.com".to_string());
        let target = input.target.unwrap_or_else(|| format!("{server_name}:443"));
        if server_name.trim().is_empty() || server_name.chars().any(char::is_whitespace) {
            return Err("REALITY server name is invalid.".to_string());
        }
        let expires = input.expires_in_seconds.unwrap_or(3600).clamp(600, 86_400);
        ControlClient::load()?.mutate_json(
            Method::POST,
            "/v1/admin/node-invitations",
            Some(json!({
                "displayName": display_name,
                "expiresInSeconds": expires,
                "initialConfiguration": {
                    "minAgentVersion": "0.1.0",
                    "xray": {
                        "listenPort": listen_port,
                        "publicPort": public_port,
                        "serverNames": [server_name],
                        "target": target
                    }
                }
            })),
            true,
        )
    })
    .await
}

#[tauri::command]
pub async fn control_node_action(input: NodeActionInput) -> Result<(), String> {
    super::run_blocking(move || {
        validate_uuid(&input.node_id, "node")?;
        if !matches!(input.action.as_str(), "approve" | "disable" | "revoke") {
            return Err("Node action is invalid.".to_string());
        }
        let response = ControlClient::load()?
            .request(
                Method::POST,
                &format!("/v1/admin/nodes/{}/{}", input.node_id, input.action),
            )
            .send()
            .map_err(|error| format!("Control Service request failed: {error}"))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(response_error(response.status(), response.text().ok()))
        }
    })
    .await
}

fn config_path() -> Result<PathBuf, String> {
    dirs::home_dir()
        .map(|home| home.join(CONFIG_RELATIVE_PATH))
        .ok_or_else(|| "Home directory is unavailable.".to_string())
}

fn ensure_private_config(path: &Path) -> Result<(), String> {
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Control Service is not installed.".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Control Service configuration path is unsafe.".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Control Service configuration is not owner-only.".to_string());
        }
    }
    Ok(())
}

fn loopback_origin(bind_address: &str) -> Result<String, String> {
    let (host, port) = bind_address
        .rsplit_once(':')
        .ok_or_else(|| "Control Service bind address is invalid.".to_string())?;
    if !matches!(host, "127.0.0.1" | "localhost") || port.parse::<u16>().is_err() {
        return Err("Control Service must use a loopback bind address.".to_string());
    }
    Ok(format!("http://{host}:{port}"))
}

fn send_json(request: RequestBuilder) -> Result<Value, String> {
    let response = request
        .send()
        .map_err(|error| format!("Control Service request failed: {error}"))?;
    let status = response.status();
    if status.is_success() {
        if status == StatusCode::NO_CONTENT {
            return Ok(Value::Null);
        }
        return response
            .json()
            .map_err(|error| format!("Control Service returned invalid JSON: {error}"));
    }
    Err(response_error(status, response.text().ok()))
}

fn response_error(status: StatusCode, body: Option<String>) -> String {
    let code = body
        .as_deref()
        .and_then(|body| serde_json::from_str::<Value>(body).ok())
        .and_then(|value| {
            value
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    match code {
        Some(code) => format!("Control Service rejected the request ({code})."),
        None => format!("Control Service request failed with HTTP {status}."),
    }
}

fn validate_label(value: &str, field: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(format!("{field} must contain 1 to 128 visible characters."));
    }
    Ok(value.to_string())
}

fn validate_uuid(value: &str, kind: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("The {kind} identifier is invalid."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_loopback_control_bindings() {
        assert_eq!(
            loopback_origin("127.0.0.1:8787").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert!(loopback_origin("0.0.0.0:8787").is_err());
        assert!(loopback_origin("127.0.0.1:not-a-port").is_err());
    }

    #[test]
    fn validates_operator_inputs() {
        assert_eq!(validate_label(" Friend ", "name").unwrap(), "Friend");
        assert!(validate_label(" ", "name").is_err());
        assert!(validate_uuid("not-a-uuid", "node").is_err());
    }
}
