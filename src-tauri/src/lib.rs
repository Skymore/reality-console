mod config_store;
mod control_api;
mod db;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use db::Db;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct XraySnapshot {
    installed: bool,
    binary_path: Option<String>,
    version: Option<String>,
    service_manageable: bool,
    service_manager: Option<String>,
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
    #[serde(default)]
    label: Option<String>,
    note: Option<String>,
    created_at: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserTraffic {
    user_id: Option<String>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrafficRefreshResponse {
    traffic: TrafficResponse,
    quotas: Vec<db::UserQuota>,
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
    original_config: Vec<u8>,
    original_metadata: Option<Vec<u8>>,
    root: Value,
    metadata: UserMetadataStore,
    link_context: RealityLinkContext,
}

#[derive(Debug, Default)]
struct XrayServiceState {
    manageable: bool,
    running: bool,
    pid: Option<u32>,
}

static PUBLIC_IPV4_CACHE: OnceLock<Mutex<Option<(Instant, String)>>> = OnceLock::new();
static PUBLIC_KEY_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static CONFIG_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const PUBLIC_IPV4_TTL: Duration = Duration::from_secs(5 * 60);
const HOMEBREW_XRAY_LABEL: &str = "homebrew.mxcl.xray";
const HOMEBREW_XRAY_PLISTS: &[&str] = &[
    "/opt/homebrew/opt/xray/homebrew.mxcl.xray.plist",
    "/usr/local/opt/xray/homebrew.mxcl.xray.plist",
];
const RELAY_PUBLIC_IPV4_ENV: &str = "RELAY_PUBLIC_IPV4";
const RELAY_PUBLIC_IPV4_FILES: &[&str] = &[
    "/opt/homebrew/etc/frp/public-ipv4",
    "/usr/local/etc/frp/public-ipv4",
    "/etc/frp/public-ipv4",
];

async fn run_blocking<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("Background task failed: {error}"))?
}

#[tauri::command]
async fn get_xray_snapshot() -> Result<XraySnapshot, String> {
    run_blocking(|| Ok(get_xray_snapshot_sync())).await
}

fn get_xray_snapshot_sync() -> XraySnapshot {
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

    let service_state = homebrew_xray_service_state();
    if installed && !service_state.manageable {
        notes.push("Xray is installed, but no manageable Homebrew service was found.".to_string());
    }

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
        service_manageable: service_state.manageable,
        service_manager: service_state
            .manageable
            .then(|| "Homebrew services".to_string()),
        running: service_state.running,
        pid: service_state.pid,
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
async fn get_vless_users() -> Result<UserListResponse, String> {
    run_blocking(get_vless_users_sync).await
}

fn get_vless_users_sync() -> Result<UserListResponse, String> {
    let loaded = load_config_with_ip(resolve_public_ipv4())?;

    Ok(UserListResponse {
        config_path: Some(loaded.path.to_string_lossy().into_owned()),
        metadata_path: Some(loaded.metadata_path.to_string_lossy().into_owned()),
        users: collect_users(&loaded.root, &loaded.metadata, &loaded.link_context)?,
    })
}

#[tauri::command]
async fn create_vless_user(input: CreateUserInput) -> Result<UserMutationResult, String> {
    run_blocking(move || create_vless_user_sync(input)).await
}

fn create_vless_user_sync(input: CreateUserInput) -> Result<UserMutationResult, String> {
    let _write_guard = lock_config_writes()?;
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;
    let timestamp = unix_timestamp();
    let preferred_label = input
        .label
        .as_deref()
        .map(validate_user_label)
        .transpose()?;
    let label = next_user_label(&loaded.root, &loaded.metadata, preferred_label.as_deref());
    ensure_label_unique(&loaded.root, &loaded.metadata, &label, None)?;
    let note = input
        .note
        .as_deref()
        .map(validate_user_note)
        .transpose()?
        .flatten();
    let user_id = Uuid::new_v4().to_string();
    let xray_email = format!("user-{user_id}");
    let client = json!({
        "id": user_id,
        "flow": "xtls-rprx-vision",
        "email": xray_email
    });

    clients_mut(&mut loaded.root)?.push(client);

    loaded.metadata.version = 2;
    loaded.metadata.users.insert(
        user_id.clone(),
        UserMetadataEntry {
            label: Some(label),
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
async fn update_user_label(
    user_id: String,
    new_label: String,
) -> Result<UserMutationResult, String> {
    run_blocking(move || update_user_label_sync(user_id, new_label)).await
}

fn update_user_label_sync(
    user_id: String,
    new_label: String,
) -> Result<UserMutationResult, String> {
    let _write_guard = lock_config_writes()?;
    validate_user_id(&user_id)?;
    let new_label = validate_user_label(&new_label)?;
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;
    if !clients(&loaded.root)?
        .iter()
        .any(|client| client.get("id").and_then(Value::as_str) == Some(user_id.as_str()))
    {
        return Err("User was not found in the current config.".to_string());
    }
    ensure_label_unique(&loaded.root, &loaded.metadata, &new_label, Some(&user_id))?;
    loaded.metadata.version = 2;
    loaded.metadata.users.entry(user_id).or_default().label = Some(new_label);

    let backup_path = persist_config_and_metadata(&loaded)?;
    let reloaded = load_config_with_ip(ip)?;

    Ok(UserMutationResult {
        backup_path,
        users: collect_users(&reloaded.root, &reloaded.metadata, &reloaded.link_context)?,
    })
}

#[tauri::command]
async fn update_user_note(user_id: String, new_note: String) -> Result<UserMutationResult, String> {
    run_blocking(move || update_user_note_sync(user_id, new_note)).await
}

fn update_user_note_sync(user_id: String, new_note: String) -> Result<UserMutationResult, String> {
    let _write_guard = lock_config_writes()?;
    validate_user_id(&user_id)?;
    let new_note = validate_user_note(&new_note)?;
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip.clone())?;

    // Verify user exists in config
    let exists = clients(&loaded.root)?
        .iter()
        .any(|c| c.get("id").and_then(Value::as_str) == Some(user_id.as_str()));
    if !exists {
        return Err("User was not found in the current config.".to_string());
    }

    loaded.metadata.version = 2;
    let entry = loaded.metadata.users.entry(user_id).or_default();
    entry.note = new_note;

    let backup_path = persist_config_and_metadata(&loaded)?;

    Ok(UserMutationResult {
        backup_path,
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
async fn update_config(input: ConfigUpdate) -> Result<String, String> {
    run_blocking(move || update_config_sync(input)).await
}

fn update_config_sync(input: ConfigUpdate) -> Result<String, String> {
    let _write_guard = lock_config_writes()?;
    validate_config_update(&input)?;
    let ip = resolve_public_ipv4();
    let mut loaded = load_config_with_ip(ip)?;

    let inbound = loaded
        .root
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| {
            inbounds
                .iter_mut()
                .find(|e| e.get("protocol").and_then(Value::as_str) == Some("vless"))
        })
        .ok_or_else(|| "Could not find VLESS inbound in config.".to_string())?;

    if let Some(port) = input.listen_port {
        inbound["port"] = json!(port);
    }

    if input.reality_target.is_some() || input.server_name.is_some() {
        let reality = inbound
            .get_mut("streamSettings")
            .and_then(|s| s.get_mut("realitySettings"))
            .ok_or_else(|| "Could not find REALITY settings in VLESS inbound.".to_string())?;
        if let Some(ref target) = input.reality_target {
            reality["target"] = json!(target.trim());
        }
        if let Some(ref sni) = input.server_name {
            reality["serverNames"] = json!([sni.trim()]);
        }
    }

    let backup_path = persist_config_and_metadata(&loaded)?;
    Ok(backup_path)
}

#[tauri::command]
async fn service_action(action: String) -> Result<String, String> {
    run_blocking(move || service_action_sync(action)).await
}

fn service_action_sync(action: String) -> Result<String, String> {
    let _write_guard = lock_config_writes()?;
    let valid = ["start", "stop", "restart"];
    if !valid.contains(&action.as_str()) {
        return Err(format!("Invalid action: {action}"));
    }

    let before = homebrew_xray_service_state();
    if !before.manageable {
        return Err(
            "The compatibility Xray installation is not managed by Homebrew services.".to_string(),
        );
    }

    let brew_binary = resolve_required_command_path("brew")?;
    let output = Command::new(&brew_binary)
        .args(["services", action.as_str(), "xray"])
        .output()
        .map_err(|error| format!("Failed to run brew services {action}: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        return Err(format!("{action} failed: {detail}"));
    }

    let expected_running = action != "stop";
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        let current = homebrew_xray_service_state();
        let restarted = action != "restart"
            || before.pid.is_none()
            || current.pid.is_some_and(|pid| Some(pid) != before.pid);
        if current.running == expected_running && restarted {
            return Ok("ok".to_string());
        }
    }

    let current = homebrew_xray_service_state();
    Err(format!(
        "Homebrew reported success, but Xray is still {}{}.",
        if current.running {
            "running"
        } else {
            "stopped"
        },
        current
            .pid
            .map(|pid| format!(" (PID {pid})"))
            .unwrap_or_default()
    ))
}

#[tauri::command]
async fn get_user_traffic() -> Result<TrafficResponse, String> {
    run_blocking(|| Ok(get_user_traffic_sync())).await
}

fn get_user_traffic_sync() -> TrafficResponse {
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
        .args([
            "api",
            "statsquery",
            "--server",
            &server,
            "-pattern",
            "user>>>",
        ])
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
async fn refresh_traffic(db: tauri::State<'_, Db>) -> Result<TrafficRefreshResponse, String> {
    let db = db.inner().clone();
    run_blocking(move || refresh_traffic_sync(&db)).await
}

fn refresh_traffic_sync(db: &Db) -> Result<TrafficRefreshResponse, String> {
    let identities = load_current_identities()?;
    db.sync_identities(&identities)?;
    let identity_by_email: HashMap<&str, &str> = identities
        .iter()
        .map(|(user_id, email)| (email.as_str(), user_id.as_str()))
        .collect();
    let mut traffic = get_user_traffic_sync();
    for entry in &mut traffic.users {
        entry.user_id = identity_by_email
            .get(entry.email.as_str())
            .map(|user_id| (*user_id).to_string());
    }
    let quotas = if traffic.available && traffic.error.is_none() {
        let stats: Vec<(String, String, u64, u64)> = traffic
            .users
            .iter()
            .filter_map(|entry| {
                entry
                    .user_id
                    .clone()
                    .map(|user_id| (user_id, entry.email.clone(), entry.uplink, entry.downlink))
            })
            .collect();
        let now = time_now();
        let current_month = format!("{}-{:02}", now.0, now.1);
        db.sync_traffic(&stats, &current_month)?
    } else {
        db.get_quotas()?
    };

    Ok(TrafficRefreshResponse { traffic, quotas })
}

#[tauri::command]
async fn sync_traffic(db: tauri::State<'_, Db>) -> Result<Vec<db::UserQuota>, String> {
    let db = db.inner().clone();
    run_blocking(move || refresh_traffic_sync(&db).map(|response| response.quotas)).await
}

#[tauri::command]
async fn pull_access_logs(db: tauri::State<'_, Db>) -> Result<usize, String> {
    let db = db.inner().clone();
    run_blocking(move || pull_access_logs_sync(&db)).await
}

fn pull_access_logs_sync(db: &Db) -> Result<usize, String> {
    // Find access log path from xray config
    let config_path = detect_config_path().ok_or("No Xray config found.")?;
    let contents =
        fs::read_to_string(&config_path).map_err(|e| format!("Cannot read config: {e}"))?;
    let root: Value =
        serde_json::from_str(&contents).map_err(|e| format!("Cannot parse config: {e}"))?;
    db.sync_identities(&identity_pairs(&root)?)?;

    let log_path = root
        .get("log")
        .and_then(|l| l.get("access"))
        .and_then(Value::as_str)
        .ok_or("Access log not configured in Xray config.")?;

    db.sync_access_log(log_path)
}

#[tauri::command]
async fn get_connection_logs(
    db: tauri::State<'_, Db>,
    user_id: Option<String>,
    limit: Option<i64>,
) -> Result<Vec<db::ConnectionLog>, String> {
    let db = db.inner().clone();
    run_blocking(move || db.get_connections(user_id.as_deref(), limit.unwrap_or(50))).await
}

#[tauri::command]
async fn get_user_analytics(
    db: tauri::State<'_, Db>,
    user_id: String,
    range: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<db::UserAnalytics, String> {
    let db = db.inner().clone();
    run_blocking(move || {
        let (from, to) = resolve_analytics_range(range.as_deref(), from, to)?;
        db.get_user_analytics(&user_id, from, to)
    })
    .await
}

fn resolve_analytics_range(
    range: Option<&str>,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<(i64, i64), String> {
    if let (Some(from), Some(to)) = (from, to) {
        if range.is_some() && range != Some("custom") {
            return Err(
                "Use either an analytics preset or an explicit range, not both.".to_string(),
            );
        }
        if from >= to {
            return Err("Analytics range must have `from` before `to`.".to_string());
        }
        return Ok((from, to));
    }
    if from.is_some() || to.is_some() || range == Some("custom") {
        return Err("Explicit analytics ranges require both `from` and `to`.".to_string());
    }

    let seconds = match range.unwrap_or("24h") {
        "24h" => 86_400,
        "7d" => 7 * 86_400,
        "30d" => 30 * 86_400,
        "90d" => 90 * 86_400,
        value => return Err(format!("Unsupported analytics range `{value}`.")),
    };
    let to = unix_timestamp() as i64;
    Ok((to - seconds, to))
}

#[tauri::command]
async fn set_user_quota(
    db: tauri::State<'_, Db>,
    user_id: String,
    quota_gb: f64,
) -> Result<(), String> {
    let db = db.inner().clone();
    run_blocking(move || {
        let quota_bytes = (quota_gb * 1_073_741_824.0) as i64;
        db.set_quota(&user_id, quota_bytes)
    })
    .await
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
async fn delete_vless_user(user_id: String) -> Result<UserMutationResult, String> {
    run_blocking(move || delete_vless_user_sync(user_id)).await
}

fn delete_vless_user_sync(user_id: String) -> Result<UserMutationResult, String> {
    let _write_guard = lock_config_writes()?;
    validate_user_id(&user_id)?;
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
    if let Some(public_ipv4) = resolve_relay_public_ipv4() {
        return Some(public_ipv4);
    }

    let cache = PUBLIC_IPV4_CACHE.get_or_init(|| Mutex::new(None));
    let mut cached = cache.lock().ok()?;

    if let Some((fetched_at, value)) = cached.as_ref() {
        if fetched_at.elapsed() < PUBLIC_IPV4_TTL {
            return Some(value.clone());
        }
    }

    let stale = cached.as_ref().map(|(_, value)| value.clone());
    let fetched = command_output(
        "curl",
        &[
            "-4",
            "-fsS",
            "--connect-timeout",
            "3",
            "https://api.ipify.org",
        ],
    );

    if let Some(value) = fetched.as_ref() {
        *cached = Some((Instant::now(), value.clone()));
    }

    fetched.or(stale)
}

fn resolve_relay_public_ipv4() -> Option<String> {
    env::var(RELAY_PUBLIC_IPV4_ENV)
        .ok()
        .and_then(|value| normalize_public_ipv4(&value))
        .or_else(|| {
            RELAY_PUBLIC_IPV4_FILES.iter().find_map(|path| {
                fs::read_to_string(path)
                    .ok()
                    .and_then(|value| normalize_public_ipv4(&value))
            })
        })
}

fn normalize_public_ipv4(value: &str) -> Option<String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .ok()
        .map(|address| address.to_string())
}

fn load_config_with_ip(public_ipv4: Option<String>) -> Result<LoadedConfig, String> {
    let path = detect_config_path()
        .map(PathBuf::from)
        .ok_or_else(|| "No known Xray config path was found.".to_string())?;

    let contents =
        fs::read(&path).map_err(|error| format!("Failed to read config file: {error}"))?;
    let root: Value = serde_json::from_slice(&contents)
        .map_err(|error| format!("Failed to parse config JSON: {error}"))?;

    let metadata_path = metadata_path_for(&path)?;
    let (metadata, original_metadata) = read_metadata(&metadata_path)?;
    let link_context = build_link_context(&root, public_ipv4);

    Ok(LoadedConfig {
        path,
        metadata_path,
        original_config: contents,
        original_metadata,
        root,
        metadata,
        link_context,
    })
}

fn persist_config_and_metadata(loaded: &LoadedConfig) -> Result<String, String> {
    let candidate = serde_json::to_string_pretty(&loaded.root)
        .map_err(|error| format!("Failed to serialize updated config: {error}"))?;
    let metadata = serde_json::to_string_pretty(&loaded.metadata)
        .map_err(|error| format!("Failed to serialize metadata: {error}"))?;
    config_store::persist_validated_pair(
        &loaded.path,
        &loaded.metadata_path,
        &loaded.original_config,
        loaded.original_metadata.as_deref(),
        candidate.as_bytes(),
        metadata.as_bytes(),
        validate_xray_config,
    )
    .map(|path| path.to_string_lossy().into_owned())
}

fn lock_config_writes() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    CONFIG_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "The config write lock is unavailable.".to_string())
}

fn validate_user_id(value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| "User ID must be a valid UUID.".to_string())
}

fn validate_user_label(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("User label cannot be empty.".to_string());
    }
    if value.chars().count() > 80 {
        return Err("User label cannot exceed 80 characters.".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("User label cannot contain control characters.".to_string());
    }
    Ok(value.to_string())
}

fn validate_user_note(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.chars().count() > 1000 {
        return Err("User note cannot exceed 1000 characters.".to_string());
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err("User note contains unsupported control characters.".to_string());
    }
    Ok(Some(value.to_string()))
}

fn validate_config_update(input: &ConfigUpdate) -> Result<(), String> {
    if input.listen_port == Some(0) {
        return Err("Listen port must be between 1 and 65535.".to_string());
    }
    if let Some(target) = input.reality_target.as_deref() {
        let target = target.trim();
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| "REALITY target must use host:port format.".to_string())?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "REALITY target has an invalid port.".to_string())?;
        if host.is_empty() || port == 0 || target.chars().any(char::is_whitespace) {
            return Err("REALITY target must contain a valid host and port.".to_string());
        }
    }
    if let Some(server_name) = input.server_name.as_deref() {
        let server_name = server_name.trim();
        if server_name.is_empty()
            || server_name.len() > 253
            || server_name.chars().any(char::is_whitespace)
            || server_name.contains('/')
            || server_name.contains(':')
        {
            return Err("REALITY server name is invalid.".to_string());
        }
    }
    Ok(())
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

        let xray_email = client
            .get("email")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| id.clone());
        let metadata_entry = metadata.users.get(&id).cloned().unwrap_or_default();
        let label = metadata_entry
            .label
            .clone()
            .unwrap_or_else(|| xray_email.clone());
        let flow = client
            .get("flow")
            .and_then(Value::as_str)
            .map(ToString::to_string);
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

    let public_key = private_key.as_deref().and_then(derive_public_key);

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
        .and_then(|inbounds| {
            inbounds
                .iter_mut()
                .find(|entry| entry.get("protocol").and_then(Value::as_str) == Some("vless"))
        })
        .and_then(|entry| entry.get_mut("settings"))
        .and_then(|settings| settings.get_mut("clients"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            "Could not find mutable `inbounds[0].settings.clients` in config.".to_string()
        })
}

fn identity_pairs(root: &Value) -> Result<Vec<(String, String)>, String> {
    clients(root)?
        .iter()
        .map(|client| {
            let user_id = client
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "Encountered a client without a valid UUID.".to_string())?;
            let xray_email = client
                .get("email")
                .and_then(Value::as_str)
                .filter(|email| !email.is_empty())
                .unwrap_or(user_id);
            Ok((user_id.to_string(), xray_email.to_string()))
        })
        .collect()
}

fn load_current_identities() -> Result<Vec<(String, String)>, String> {
    let config_path = detect_config_path().ok_or("No Xray config found.")?;
    let contents =
        fs::read_to_string(config_path).map_err(|e| format!("Cannot read Xray config: {e}"))?;
    let root: Value =
        serde_json::from_str(&contents).map_err(|e| format!("Cannot parse Xray config: {e}"))?;
    identity_pairs(&root)
}

fn metadata_path_for(config_path: &Path) -> Result<PathBuf, String> {
    let parent = config_path
        .parent()
        .ok_or_else(|| "Config path has no parent directory.".to_string())?;
    Ok(parent.join("private-network.users.json"))
}

fn read_metadata(path: &Path) -> Result<(UserMetadataStore, Option<Vec<u8>>), String> {
    if !path.exists() {
        return Ok((
            UserMetadataStore {
                version: 2,
                users: HashMap::new(),
            },
            None,
        ));
    }

    let contents =
        fs::read(path).map_err(|error| format!("Failed to read metadata file: {error}"))?;
    let metadata: UserMetadataStore = serde_json::from_slice(&contents)
        .map_err(|error| format!("Failed to parse metadata JSON: {error}"))?;
    if metadata.version != 1 && metadata.version != 2 {
        return Err(format!(
            "Unsupported metadata version: {}.",
            metadata.version
        ));
    }

    Ok((metadata, Some(contents)))
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

    Err(format!(
        "Updated config did not pass `xray -test`: {detail}"
    ))
}

fn derive_public_key(private_key: &str) -> Option<String> {
    let cache = PUBLIC_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(value) = cache.lock().ok()?.get(private_key).cloned() {
        return Some(value);
    }

    let xray_binary = resolve_command_path("xray")?;
    let output = command_output_at(&xray_binary, &["x25519", "-i", private_key])?;
    let public_key = output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Password (PublicKey): ")
            .map(ToString::to_string)
    })?;

    cache
        .lock()
        .ok()?
        .insert(private_key.to_string(), public_key.clone());
    Some(public_key)
}

fn next_user_label(root: &Value, metadata: &UserMetadataStore, preferred: Option<&str>) -> String {
    if let Some(preferred) = preferred.and_then(normalize_optional) {
        return preferred;
    }

    let existing = collect_users(root, metadata, &RealityLinkContext::default())
        .map(|users| users.into_iter().map(|user| user.label).collect::<Vec<_>>())
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

fn ensure_label_unique(
    root: &Value,
    metadata: &UserMetadataStore,
    label: &str,
    excluding_user_id: Option<&str>,
) -> Result<(), String> {
    let duplicate = collect_users(root, metadata, &RealityLinkContext::default())?
        .into_iter()
        .any(|user| user.id != excluding_user_id.unwrap_or_default() && user.label == label);
    if duplicate {
        Err("User label is already in use.".to_string())
    } else {
        Ok(())
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

fn homebrew_xray_service_state() -> XrayServiceState {
    let manageable = resolve_command_path("brew").is_some()
        && HOMEBREW_XRAY_PLISTS
            .iter()
            .any(|path| Path::new(path).is_file());
    if !manageable {
        return XrayServiceState::default();
    }

    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        });
    let Some(uid) = uid else {
        return XrayServiceState {
            manageable,
            ..XrayServiceState::default()
        };
    };

    let output = Command::new("/bin/launchctl")
        .args(["print", format!("gui/{uid}/{HOMEBREW_XRAY_LABEL}").as_str()])
        .output();
    let Ok(output) = output else {
        return XrayServiceState {
            manageable,
            ..XrayServiceState::default()
        };
    };
    if !output.status.success() {
        return XrayServiceState {
            manageable,
            ..XrayServiceState::default()
        };
    }

    let description = String::from_utf8_lossy(&output.stdout);
    let (running, pid) = parse_launchctl_service(&description);
    XrayServiceState {
        manageable,
        running,
        pid,
    }
}

fn parse_launchctl_service(description: &str) -> (bool, Option<u32>) {
    let running = description
        .lines()
        .any(|line| line.trim() == "state = running");
    let pid = description.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|value| value.parse::<u32>().ok())
    });
    (running && pid.is_some(), pid)
}

fn resolve_required_command_path(program: &str) -> Result<PathBuf, String> {
    resolve_command_path(program)
        .ok_or_else(|| format!("`{program}` was not found in PATH or known install locations."))
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
            user_id: None,
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
            refresh_traffic,
            sync_traffic,
            set_user_quota,
            pull_access_logs,
            get_connection_logs,
            get_user_analytics,
            service_action,
            control_api::get_control_snapshot,
            control_api::create_control_account,
            control_api::update_control_account_nodes,
            control_api::set_control_account_status,
            control_api::create_connect_setup,
            control_api::create_node_setup,
            control_api::control_node_action
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_user_fields() {
        assert_eq!(validate_user_label("  Friend  ").unwrap(), "Friend");
        assert!(validate_user_label(" ").is_err());
        assert!(validate_user_label(&"x".repeat(81)).is_err());
        assert_eq!(
            validate_user_note("  first line\nsecond line  ").unwrap(),
            Some("first line\nsecond line".to_string())
        );
        assert_eq!(validate_user_note("  ").unwrap(), None);
    }

    #[test]
    fn rejects_invalid_config_updates() {
        assert!(validate_config_update(&ConfigUpdate {
            listen_port: Some(0),
            reality_target: None,
            server_name: None,
        })
        .is_err());
        assert!(validate_config_update(&ConfigUpdate {
            listen_port: None,
            reality_target: Some("missing-port".to_string()),
            server_name: None,
        })
        .is_err());
        assert!(validate_config_update(&ConfigUpdate {
            listen_port: None,
            reality_target: None,
            server_name: Some("bad name".to_string()),
        })
        .is_err());
    }

    #[test]
    fn accepts_current_reality_settings() {
        assert!(validate_config_update(&ConfigUpdate {
            listen_port: Some(443),
            reality_target: Some("www.example.com:443".to_string()),
            server_name: Some("www.example.com".to_string()),
        })
        .is_ok());
    }

    #[test]
    fn normalizes_relay_public_ipv4_values() {
        assert_eq!(
            normalize_public_ipv4(" 203.0.113.10\n"),
            Some("203.0.113.10".to_string())
        );
        assert_eq!(normalize_public_ipv4("203.0.113.10:443"), None);
        assert_eq!(normalize_public_ipv4("not-an-ip"), None);
        assert_eq!(normalize_public_ipv4("2001:db8::1"), None);
    }

    #[test]
    fn parses_launchctl_xray_state_without_matching_other_processes() {
        let running = r#"
            state = running
            pid = 56412
            last exit code = (never exited)
        "#;
        assert_eq!(parse_launchctl_service(running), (true, Some(56_412)));

        let stopped = r#"
            state = waiting
            last exit code = 0
        "#;
        assert_eq!(parse_launchctl_service(stopped), (false, None));
    }

    #[test]
    fn resolves_analytics_presets_and_explicit_ranges() {
        for (preset, seconds) in [
            ("24h", 86_400),
            ("7d", 7 * 86_400),
            ("30d", 30 * 86_400),
            ("90d", 90 * 86_400),
        ] {
            let (from, to) = resolve_analytics_range(Some(preset), None, None).unwrap();
            assert_eq!(to - from, seconds);
        }
        assert_eq!(
            resolve_analytics_range(Some("custom"), Some(10), Some(20)).unwrap(),
            (10, 20)
        );
        assert!(resolve_analytics_range(None, Some(20), Some(10)).is_err());
        assert!(resolve_analytics_range(Some("1y"), None, None).is_err());
    }
}
