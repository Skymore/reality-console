mod db;

use std::env;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use db::Db;
use dirs;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XraySnapshot {
    installed: bool,
    binary_path: Option<String>,
    version: Option<String>,
    running: bool,
    pid: Option<u32>,
    config_path: Option<String>,
    public_ipv4: Option<String>,
    lan_ip: Option<String>,
    listen_port: Option<u16>,
    user_count: Option<usize>,
    reality_target: Option<String>,
    server_name: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedUser {
    id: String,
    label: String,
    flow: Option<String>,
    note: Option<String>,
    created_at: Option<u64>,
    share_link: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserListResponse {
    config_path: Option<String>,
    metadata_path: Option<String>,
    users: Vec<ManagedUser>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserMutationResult {
    backup_path: String,
    users: Vec<ManagedUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserInput {
    label: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct UserMetadataStore {
    version: u8,
    users: HashMap<String, UserMetadataEntry>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
struct UserMetadataEntry {
    note: Option<String>,
    created_at: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserTraffic {
    email: String,
    uplink: u64,
    downlink: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficResponse {
    available: bool,
    api_port: Option<u16>,
    users: Vec<UserTraffic>,
    error: Option<String>,
}

#[derive(Default)]
struct ConfigInspection {
    listen_port: Option<u16>,
    user_count: Option<usize>,
    reality_target: Option<String>,
    server_name: Option<String>,
}

#[derive(Default)]
struct RealityLinkContext {
    public_ipv4: Option<String>,
    listen_port: Option<u16>,
    server_name: Option<String>,
    public_key: Option<String>,
    short_id: Option<String>,
}

struct LoadedConfig {
    path: PathBuf,
    metadata_path: PathBuf,
    root: Value,
    metadata: UserMetadataStore,
    link_context: RealityLinkContext,
}

#[tauri::command]
fn get_xray_snapshot() -> XraySnapshot {
    let mut notes = Vec::new();

    let xray_binary = resolve_command_path("xray");
    let binary_path = xray_binary
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let installed = xray_binary.is_some();

    let version = if let Some(binary) = xray_binary.as_ref() {
        command_output_at(binary, &["version"])
            .and_then(|output| output.lines().next().map(|line| line.trim().to_string()))
    } else {
        notes.push("`xray` was not found in PATH or known install locations.".to_string());
        None
    };

    let (running, pid) = brew_service_status("xray")
        .or_else(|| pgrep_status("xray"))
        .unwrap_or_else(|| {
            notes.push("Could not determine process state from brew services or pgrep.".to_string());
            (false, None)
        });

    let config_path = detect_config_path();
    let public_ipv4: Option<String> = resolve_public_ipv4().or_else(|| {
        notes.push("Public IPv4 lookup failed.".to_string());
        None
    });
    let lan_ip = detect_lan_ip().or_else(|| {
        notes.push("LAN IP detection failed.".to_string());
        None
    });

    let mut listen_port = None;
    let mut user_count = None;
    let mut reality_target = None;
    let mut server_name = None;

    if let Some(path) = config_path.as_deref() {
        match inspect_config(path) {
            Some(inspected) => {
                listen_port = inspected.listen_port;
                user_count = inspected.user_count;
                reality_target = inspected.reality_target;
                server_name = inspected.server_name;
            }
            None => notes.push("Config file was found but could not be parsed.".to_string()),
        }
    } else {
        notes.push("No known Xray config path was found.".to_string());
    }

    XraySnapshot {
        installed,
        binary_path,
        version,
        running,
        pid,
        config_path,
        public_ipv4,
        lan_ip,
        listen_port,
        user_count,
        reality_target,
        server_name,
        notes,
    }
}

#[tauri::command]
fn get_vless_users() -> Result<UserListResponse, String> {
    let loaded = load_config_with_ip(resolve_public_ipv4())?;

    Ok(UserListResponse {
        config_path: Some(loaded.path.to_string_lossy().into_owned()),
        metadata_path: Some(loaded.metadata_path.to_string_lossy().into_owned()),
        users: collect_users(&loaded.root, &loaded.metadata, &loaded.link_context)?,
    })
}

#[tauri::command]
fn create_vless_user(input: CreateUserInput) -> Result<UserMutationResult, String> {
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;
    let timestamp = unix_timestamp();
    let label = next_user_label(&loaded.root, input.label.as_deref());
    let note = input.note.and_then(|value| normalize_optional(&value));
    let user_id = Uuid::new_v4().to_string();
    let client = json!({
        "id": user_id,
        "flow": "xtls-rprx-vision",
        "email": label
    });

    clients_mut(&mut loaded.root)?
        .push(client);

    loaded.metadata.version = 1;
    loaded.metadata.users.insert(
        user_id.clone(),
        UserMetadataEntry {
            note,
            created_at: Some(timestamp),
        },
    );

    let backup_path = persist_config_and_metadata(&loaded)?;
    let reloaded = load_config_with_ip(ip)?;

    Ok(UserMutationResult {
        backup_path,
        users: collect_users(&reloaded.root, &reloaded.metadata, &reloaded.link_context)?,
    })
}

#[tauri::command]
fn update_user_label(user_id: String, new_label: String) -> Result<UserMutationResult, String> {
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;
    let clients = clients_mut(&mut loaded.root)?;

    let found = clients.iter_mut().find(|client| {
        client.get("id").and_then(Value::as_str) == Some(user_id.as_str())
    });

    match found {
        Some(client) => {
            client["email"] = json!(new_label.trim());
        }
        None => return Err("User was not found in the current config.".to_string()),
    }

    let backup_path = persist_config_and_metadata(&loaded)?;
    let reloaded = load_config_with_ip(ip)?;

    Ok(UserMutationResult {
        backup_path,
        users: collect_users(&reloaded.root, &reloaded.metadata, &reloaded.link_context)?,
    })
}

#[tauri::command]
fn update_user_note(user_id: String, new_note: String) -> Result<UserMutationResult, String> {
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;

    // Verify user exists in config
    let exists = clients(&loaded.root)?.iter().any(|c| {
        c.get("id").and_then(Value::as_str) == Some(user_id.as_str())
    });
    if !exists {
        return Err("User was not found in the current config.".to_string());
    }

    let trimmed = new_note.trim();
    let entry = loaded.metadata.users.entry(user_id).or_default();
    entry.note = if trimmed.is_empty() { None } else { Some(trimmed.to_string()) };

    write_metadata(&loaded.metadata_path, &loaded.metadata)?;

    Ok(UserMutationResult {
        backup_path: loaded.metadata_path.to_string_lossy().into_owned(),
        users: collect_users(&loaded.root, &loaded.metadata, &loaded.link_context)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigUpdate {
    listen_port: Option<u16>,
    reality_target: Option<String>,
    server_name: Option<String>,
}

#[tauri::command]
fn update_config(input: ConfigUpdate) -> Result<String, String> {
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip)?;

    let inbound = loaded.root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| inbounds.iter_mut().find(|e| e.get("protocol").and_then(Value::as_str) == Some("vless")))
        .ok_or_else(|| "Could not find VLESS inbound in config.".to_string())?;

    if let Some(port) = input.listen_port {
        inbound["port"] = json!(port);
    }

    if let Some(ref target) = input.reality_target {
        if let Some(reality) = inbound.get_mut("streamSettings").and_then(|s| s.get_mut("realitySettings")) {
            reality["target"] = json!(target);
        }
    }

    if let Some(ref sni) = input.server_name {
        if let Some(reality) = inbound.get_mut("streamSettings").and_then(|s| s.get_mut("realitySettings")) {
            reality["serverNames"] = json!([sni]);
        }
    }

    let backup_path = persist_config_and_metadata(&loaded)?;
    Ok(backup_path)
}

#[tauri::command]
fn service_action(action: String) -> Result<String, String> {
    let valid = ["start", "stop", "restart"];
    if !valid.contains(&action.as_str()) {
        return Err(format!("Invalid action: {action}"));
    }

    let brew_binary = resolve_required_command_path("brew")?;
    let output = Command::new(&brew_binary)
        .args(["services", action.as_str(), "xray"])
        .output()
        .map_err(|error| format!("Failed to run brew services {action}: {error}"))?;

    if output.status.success() {
        Ok("ok".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(format!("{action} failed: {stderr}"))
    }
}

#[tauri::command]
fn get_user_traffic() -> TrafficResponse {
    let config_path = match detect_config_path() {
        Some(path) => path,
        None => {
            return TrafficResponse {
                available: false,
                api_port: None,
                users: vec![],
                error: Some("No Xray config found.".to_string()),
            }
        }
    };

    let contents = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(e) => {
            return TrafficResponse {
                available: false,
                api_port: None,
                users: vec![],
                error: Some(format!("Cannot read config: {e}")),
            }
        }
    };

    let root: Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            return TrafficResponse {
                available: false,
                api_port: None,
                users: vec![],
                error: Some(format!("Cannot parse config: {e}")),
            }
        }
    };

    let has_stats = root.get("stats").is_some();
    let api_port = find_api_port(&root);

    if !has_stats || api_port.is_none() {
        return TrafficResponse {
            available: false,
            api_port: None,
            users: vec![],
            error: Some("Stats API is not enabled in the Xray config. Add \"stats\", \"api\", and \"policy\" sections to enable.".to_string()),
        };
    }

    let port = api_port.unwrap();
    let server = format!("127.0.0.1:{port}");

    let xray_binary = match resolve_required_command_path("xray") {
        Ok(path) => path,
        Err(error) => {
            return TrafficResponse {
                available: false,
                api_port: Some(port),
                users: vec![],
                error: Some(error),
            }
        }
    };

    match Command::new(&xray_binary)
        .args(["api", "statsquery", "--server", &server, "-pattern", "user>>>"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let users = parse_traffic_stats(&stdout);
            TrafficResponse {
                available: true,
                api_port: Some(port),
                users,
                error: None,
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            TrafficResponse {
                available: true,
                api_port: Some(port),
                users: vec![],
                error: Some(format!("Stats query failed: {stderr}")),
            }
        }
        Err(e) => TrafficResponse {
            available: true,
            api_port: Some(port),
            users: vec![],
            error: Some(format!("Failed to run xray api: {e}")),
        },
    }
}

#[tauri::command]
fn sync_traffic(db: tauri::State<'_, Db>) -> Result<Vec<db::UserQuota>, String> {
    // Get live stats from xray
    let config_path = detect_config_path().ok_or("No Xray config found.")?;
    let contents = fs::read_to_string(&config_path).map_err(|e| format!("Cannot read config: {e}"))?;
    let root: Value = serde_json::from_str(&contents).map_err(|e| format!("Cannot parse config: {e}"))?;

    let has_stats = root.get("stats").is_some();
    let api_port = find_api_port(&root);

    if !has_stats || api_port.is_none() {
        return db.get_quotas();
    }

    let port = api_port.unwrap();
    let server = format!("127.0.0.1:{port}");
    let xray_binary = resolve_required_command_path("xray")?;

    let live_stats = match Command::new(&xray_binary)
        .args(["api", "statsquery", "--server", &server, "-pattern", "user>>>"])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_traffic_stats(&stdout)
        }
        _ => vec![],
    };

    let stats_tuples: Vec<(String, u64, u64)> = live_stats
        .into_iter()
        .map(|t| (t.email, t.uplink, t.downlink))
        .collect();

    let now = time_now();
    let current_month = format!("{}-{:02}", now.0, now.1);

    db.sync_traffic(&stats_tuples, &current_month)
}

#[tauri::command]
fn pull_access_logs(db: tauri::State<'_, Db>) -> Result<usize, String> {
    // Find access log path from xray config
    let config_path = detect_config_path().ok_or("No Xray config found.")?;
    let contents = fs::read_to_string(&config_path).map_err(|e| format!("Cannot read config: {e}"))?;
    let root: Value = serde_json::from_str(&contents).map_err(|e| format!("Cannot parse config: {e}"))?;

    let log_path = root
        .get("log")
        .and_then(|l| l.get("access"))
        .and_then(Value::as_str)
        .ok_or("Access log not configured in Xray config.")?;

    db.sync_access_log(log_path)
}

#[tauri::command]
fn get_connection_logs(db: tauri::State<'_, Db>, user_email: Option<String>, limit: Option<i64>) -> Result<Vec<db::ConnectionLog>, String> {
    db.get_connections(user_email.as_deref(), limit.unwrap_or(50))
}

#[tauri::command]
fn set_user_quota(db: tauri::State<'_, Db>, user_id: String, quota_gb: f64) -> Result<(), String> {
    let quota_bytes = (quota_gb * 1_073_741_824.0) as i64;
    db.set_quota(&user_id, quota_bytes)
}

fn time_now() -> (i32, u32) {
    // Returns (year, month)
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs / 86400 + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32)
}

#[tauri::command]
fn delete_vless_user(user_id: String) -> Result<UserMutationResult, String> {
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;
    let clients = clients_mut(&mut loaded.root)?;
    let original_len = clients.len();

    clients.retain(|client| {
        client
            .get("id")
            .and_then(Value::as_str)
            .map(|id| id != user_id)
            .unwrap_or(true)
    });

    if clients.len() == original_len {
        return Err("User was not found in the current config.".to_string());
    }

    loaded.metadata.users.remove(&user_id);

    let backup_path = persist_config_and_metadata(&loaded)?;
    let reloaded = load_config_with_ip(ip)?;

    Ok(UserMutationResult {
        backup_path,
        users: collect_users(&reloaded.root, &reloaded.metadata, &reloaded.link_context)?,
    })
}

fn resolve_public_ipv4() -> Option<String> {
    command_output("curl", &["-4", "-fsS", "--connect-timeout", "3", "https://api.ipify.org"])
}

fn load_config_with_ip(public_ipv4: Option<String>) -> Result<LoadedConfig, String> {
    let path = detect_config_path()
        .map(PathBuf::from)
        .ok_or_else(|| "No known Xray config path was found.".to_string())?;

    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("Failed to read config file: {error}"))?;
    let root: Value =
        serde_json::from_str(&contents).map_err(|error| format!("Failed to parse config JSON: {error}"))?;

    let metadata_path = metadata_path_for(&path)?;
    let metadata = read_metadata(&metadata_path)?;
    let link_context = build_link_context(&root, public_ipv4);

    Ok(LoadedConfig {
        path,
        metadata_path,
        root,
        metadata,
        link_context,
    })
}

fn persist_config_and_metadata(loaded: &LoadedConfig) -> Result<String, String> {
    let candidate = serde_json::to_string_pretty(&loaded.root)
        .map_err(|error| format!("Failed to serialize updated config: {error}"))?;

    let temp_path = temporary_path_for(&loaded.path);
    fs::write(&temp_path, candidate).map_err(|error| format!("Failed to write temp config: {error}"))?;

    if let Err(error) = validate_xray_config(&temp_path) {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }

    let backup_path = create_backup(&loaded.path)?;

    fs::rename(&temp_path, &loaded.path)
        .map_err(|error| format!("Failed to replace config file: {error}"))?;

    write_metadata(&loaded.metadata_path, &loaded.metadata)?;

    Ok(backup_path)
}

fn collect_users(
    root: &Value,
    metadata: &UserMetadataStore,
    link_context: &RealityLinkContext,
) -> Result<Vec<ManagedUser>, String> {
    let clients = clients(root)?;
    let mut users = Vec::with_capacity(clients.len());

    for client in clients {
        let id = client
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "Encountered a client without a valid UUID.".to_string())?
            .to_string();

        let label = client
            .get("email")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| id.clone());
        let flow = client
            .get("flow")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let metadata_entry = metadata.users.get(&id).cloned().unwrap_or_default();

        users.push(ManagedUser {
            id: id.clone(),
            label: label.clone(),
            flow: flow.clone(),
            note: metadata_entry.note.clone(),
            created_at: metadata_entry.created_at,
            share_link: build_share_link(&id, &label, flow.as_deref(), link_context),
        });
    }

    Ok(users)
}

fn build_link_context(root: &Value, public_ipv4: Option<String>) -> RealityLinkContext {
    let inspected = inspect_root(root).unwrap_or_default();
    let inbound = vless_inbound(root);

    let private_key = inbound
        .and_then(|entry| entry.get("streamSettings"))
        .and_then(|settings| settings.get("realitySettings"))
        .and_then(|settings| settings.get("privateKey"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let public_key = private_key
        .as_deref()
        .and_then(derive_public_key);

    let short_id = inbound
        .and_then(|entry| entry.get("streamSettings"))
        .and_then(|settings| settings.get("realitySettings"))
        .and_then(|settings| settings.get("shortIds"))
        .and_then(Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .map(ToString::to_string);

    RealityLinkContext {
        public_ipv4,
        listen_port: inspected.listen_port,
        server_name: inspected.server_name,
        public_key,
        short_id,
    }
}

fn build_share_link(
    user_id: &str,
    label: &str,
    flow: Option<&str>,
    link_context: &RealityLinkContext,
) -> Option<String> {
    let host = link_context.public_ipv4.as_deref()?;
    let port = link_context.listen_port?;
    let server_name = link_context.server_name.as_deref()?;
    let public_key = link_context.public_key.as_deref()?;
    let short_id = link_context.short_id.as_deref()?;
    let flow = flow.unwrap_or("xtls-rprx-vision");
    let fragment = {
        let slug = slugify(label);
        if slug.is_empty() {
            format!("user-{}", &user_id[..8])
        } else {
            slug
        }
    };

    Some(format!(
        "vless://{user_id}@{host}:{port}?encryption=none&flow={flow}&security=reality&sni={server_name}&fp=chrome&pbk={public_key}&sid={short_id}&type=tcp&headerType=none#{fragment}"
    ))
}

fn inspect_config(path: &str) -> Option<ConfigInspection> {
    let contents = fs::read_to_string(path).ok()?;
    let root: Value = serde_json::from_str(&contents).ok()?;
    inspect_root(&root)
}

fn inspect_root(root: &Value) -> Option<ConfigInspection> {
    let inbound = vless_inbound(root)?;

    let listen_port = inbound
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());

    let user_count = inbound
        .get("settings")
        .and_then(|settings| settings.get("clients"))
        .and_then(Value::as_array)
        .map(|clients| clients.len());

    let reality_settings = inbound
        .get("streamSettings")
        .and_then(|settings| settings.get("realitySettings"));

    let reality_target = reality_settings
        .and_then(|settings| settings.get("target"))
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let server_name = reality_settings
        .and_then(|settings| settings.get("serverNames"))
        .and_then(Value::as_array)
        .and_then(|names| names.first())
        .and_then(Value::as_str)
        .map(ToString::to_string);

    Some(ConfigInspection {
        listen_port,
        user_count,
        reality_target,
        server_name,
    })
}

fn vless_inbound(root: &Value) -> Option<&Value> {
    root.get("inbounds")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("protocol").and_then(Value::as_str) == Some("vless"))
}

fn clients(root: &Value) -> Result<&Vec<Value>, String> {
    vless_inbound(root)
        .and_then(|entry| entry.get("settings"))
        .and_then(|settings| settings.get("clients"))
        .and_then(Value::as_array)
        .ok_or_else(|| "Could not find a VLESS inbound with clients in config.".to_string())
}

fn clients_mut(root: &mut Value) -> Result<&mut Vec<Value>, String> {
    root.get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| inbounds.iter_mut().find(|entry| entry.get("protocol").and_then(Value::as_str) == Some("vless")))
        .and_then(|entry| entry.get_mut("settings"))
        .and_then(|settings| settings.get_mut("clients"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Could not find mutable `inbounds[0].settings.clients` in config.".to_string())
}

fn metadata_path_for(config_path: &Path) -> Result<PathBuf, String> {
    let parent = config_path
        .parent()
        .ok_or_else(|| "Config path has no parent directory.".to_string())?;
    Ok(parent.join("reality-console.users.json"))
}

fn read_metadata(path: &Path) -> Result<UserMetadataStore, String> {
    if !path.exists() {
        return Ok(UserMetadataStore {
            version: 1,
            users: HashMap::new(),
        });
    }

    let contents =
        fs::read_to_string(path).map_err(|error| format!("Failed to read metadata file: {error}"))?;
    let metadata: UserMetadataStore = serde_json::from_str(&contents)
        .map_err(|error| format!("Failed to parse metadata JSON: {error}"))?;

    Ok(metadata)
}

fn write_metadata(path: &Path, metadata: &UserMetadataStore) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(metadata)
        .map_err(|error| format!("Failed to serialize metadata: {error}"))?;
    fs::write(path, contents).map_err(|error| format!("Failed to write metadata file: {error}"))
}

fn create_backup(path: &Path) -> Result<String, String> {
    let timestamp = unix_timestamp();
    let file_stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("config");
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("json");
    let backup_name = format!("{file_stem}.backup-{timestamp}.{extension}");
    let backup_path = path
        .parent()
        .ok_or_else(|| "Config path has no parent directory.".to_string())?
        .join(backup_name);

    fs::copy(path, &backup_path).map_err(|error| format!("Failed to create backup: {error}"))?;

    Ok(backup_path.to_string_lossy().into_owned())
}

fn temporary_path_for(path: &Path) -> PathBuf {
    let timestamp = unix_timestamp();
    let stem = path.file_stem().and_then(|v| v.to_str()).unwrap_or("config");
    let ext = path.extension().and_then(|v| v.to_str()).unwrap_or("json");
    path.with_file_name(format!("{stem}.tmp-{timestamp}.{ext}"))
}

fn validate_xray_config(path: &Path) -> Result<(), String> {
    let path_string = path.to_string_lossy().into_owned();
    let xray_binary = resolve_required_command_path("xray")?;
    let output = Command::new(&xray_binary)
        .args(["run", "-c", path_string.as_str(), "-test"])
        .output()
        .map_err(|error| format!("Failed to run xray config validation: {error}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "Unknown xray validation failure.".to_string()
    };

    Err(format!("Updated config did not pass `xray -test`: {detail}"))
}

fn derive_public_key(private_key: &str) -> Option<String> {
    let xray_binary = resolve_command_path("xray")?;
    let output = command_output_at(&xray_binary, &["x25519", "-i", private_key])?;
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Password (PublicKey): ")
            .map(ToString::to_string)
    })
}

fn next_user_label(root: &Value, preferred: Option<&str>) -> String {
    if let Some(preferred) = preferred.and_then(normalize_optional) {
        return preferred;
    }

    let existing: Vec<String> = clients(root)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|client| client.get("email").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut index = 1;
    loop {
        let candidate = format!("friend-{index}");
        if !existing.iter().any(|entry| entry == &candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn normalize_optional(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn slugify(value: &str) -> String {
    let slug = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else if character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();

    slug.trim_matches('-').to_string()
}

fn detect_config_path() -> Option<String> {
    let candidates = [
        "/opt/homebrew/etc/xray/config.json",
        "/usr/local/etc/xray/config.json",
        "/etc/xray/config.json",
    ];

    candidates
        .iter()
        .find(|candidate| Path::new(candidate).exists())
        .map(|candidate| candidate.to_string())
}

fn detect_lan_ip() -> Option<String> {
    let route_output = command_output("route", &["-n", "get", "default"])?;
    let interface = route_output
        .lines()
        .find(|line| line.trim_start().starts_with("interface:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)?
        .to_string();

    command_output("ipconfig", &["getifaddr", interface.as_str()])
}

fn brew_service_status(service: &str) -> Option<(bool, Option<u32>)> {
    let output = command_output("brew", &["services", "info", service])?;
    let running = output
        .lines()
        .find(|line| line.trim_start().starts_with("Running:"))
        .map(|line| line.contains("true"))?;

    let pid = output
        .lines()
        .find(|line| line.trim_start().starts_with("PID:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|value| value.trim().parse::<u32>().ok());

    Some((running, pid))
}

fn pgrep_status(process: &str) -> Option<(bool, Option<u32>)> {
    let output = command_output("pgrep", &["-x", process])?;
    let pid = output.lines().next()?.trim().parse::<u32>().ok()?;
    Some((true, Some(pid)))
}

fn resolve_required_command_path(program: &str) -> Result<PathBuf, String> {
    resolve_command_path(program).ok_or_else(|| {
        format!("`{program}` was not found in PATH or known install locations.")
    })
}

fn resolve_command_path(program: &str) -> Option<PathBuf> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }

    if let Some(path_env) = env::var_os("PATH") {
        for directory in env::split_paths(&path_env) {
            let path = directory.join(program);
            if path.is_file() {
                return Some(path);
            }
        }
    }

    for fallback in command_fallbacks(program) {
        let path = PathBuf::from(fallback);
        if path.is_file() {
            return Some(path);
        }
    }

    None
}

fn command_fallbacks(program: &str) -> &'static [&'static str] {
    match program {
        "xray" => &["/opt/homebrew/bin/xray", "/usr/local/bin/xray"],
        "brew" => &["/opt/homebrew/bin/brew", "/usr/local/bin/brew"],
        _ => &[],
    }
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let resolved = resolve_command_path(program)?;
    command_output_at(&resolved, args)
}

fn command_output_at(program: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}

fn find_api_port(root: &Value) -> Option<u16> {
    let inbounds = root.get("inbounds")?.as_array()?;
    for inbound in inbounds {
        let tag = inbound.get("tag").and_then(Value::as_str);
        let protocol = inbound.get("protocol").and_then(Value::as_str);
        if tag == Some("api") && protocol == Some("dokodemo-door") {
            return inbound
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok());
        }
    }
    None
}

fn parse_traffic_stats(output: &str) -> Vec<UserTraffic> {
    // Output is JSON: {"stat": [{"name": "user>>>email>>>traffic>>>uplink", "value": 123}, ...]}
    let mut traffic_map: HashMap<String, (u64, u64)> = HashMap::new();

    let root: Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let stats = match root.get("stat").and_then(Value::as_array) {
        Some(arr) => arr,
        None => return vec![],
    };

    for entry in stats {
        let name = match entry.get("name").and_then(Value::as_str) {
            Some(n) => n,
            None => continue,
        };
        let value = entry.get("value").and_then(Value::as_u64).unwrap_or(0);

        // name format: "user>>>email>>>traffic>>>uplink"
        let parts: Vec<&str> = name.split(">>>").collect();
        if parts.len() == 4 && parts[0] == "user" && parts[2] == "traffic" {
            let email = parts[1].to_string();
            let entry = traffic_map.entry(email).or_insert((0, 0));
            match parts[3] {
                "uplink" => entry.0 = value,
                "downlink" => entry.1 = value,
                _ => {}
            }
        }
    }

    traffic_map
        .into_iter()
        .map(|(email, (uplink, downlink))| UserTraffic {
            email,
            uplink,
            downlink,
        })
        .collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Init DB in the same directory as the xray config, or fallback to home
    let db_dir = detect_config_path()
        .and_then(|p| Path::new(&p).parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")));
    let db = Db::open(&db_dir).expect("Failed to open database");

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(db)
        .invoke_handler(tauri::generate_handler![
            get_xray_snapshot,
            get_vless_users,
            create_vless_user,
            delete_vless_user,
            update_user_label,
            update_user_note,
            update_config,
            get_user_traffic,
            sync_traffic,
            set_user_quota,
            pull_access_logs,
            get_connection_logs,
            service_action
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
