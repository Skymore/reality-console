//! Closed headless command path for installed-artifact operations and acceptance.

use crate::connect_service::ConnectSnapshot;
use crate::error::ClientError;
use crate::member_setup::SetupSessionStore;
use crate::runtime::ConnectRuntimeRegistry;
use crate::selection::SelectionMode;
use crate::session::DeviceMetadata;
use crate::state::ProxyMode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager as _};
use zeroize::Zeroizing;

const HEADLESS_SCHEMA_VERSION: u16 = 1;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_DEVICE_NAME_BYTES: usize = 128;
const MAX_HOLD_SECONDS: u16 = 300;

pub struct HeadlessInvocation {
    request: HeadlessRequest,
    output: Arc<HeadlessOutput>,
}

impl HeadlessInvocation {
    pub fn from_stdin(output_path: &Path) -> Result<Self, ClientError> {
        if !output_path.is_absolute() {
            return Err(headless_error("headless_output_path_invalid"));
        }
        let output = Arc::new(HeadlessOutput::create(output_path)?);
        let request = (|| {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| headless_error("headless_request_read_failed"))?;
            if bytes.is_empty()
                || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES
            {
                zeroize::Zeroize::zeroize(&mut bytes);
                return Err(headless_error("headless_request_size_invalid"));
            }
            let request = serde_json::from_slice::<HeadlessRequest>(&bytes).map_err(|_| {
                zeroize::Zeroize::zeroize(&mut bytes);
                headless_error("headless_request_invalid")
            })?;
            zeroize::Zeroize::zeroize(&mut bytes);
            request.validate()?;
            Ok::<_, ClientError>(request)
        })();
        match request {
            Ok(request) => Ok(Self { request, output }),
            Err(error) => {
                let _ = output.write(&HeadlessResponse::error(&error));
                Err(error)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeadlessRequest {
    schema_version: u16,
    operation: HeadlessOperation,
}

impl HeadlessRequest {
    fn validate(&self) -> Result<(), ClientError> {
        if self.schema_version != HEADLESS_SCHEMA_VERSION {
            return Err(headless_error("headless_schema_unsupported"));
        }
        match &self.operation {
            HeadlessOperation::Setup { device_name, .. } => {
                let trimmed = device_name.trim();
                if trimmed.is_empty()
                    || trimmed.len() != device_name.len()
                    || device_name.len() > MAX_DEVICE_NAME_BYTES
                {
                    return Err(headless_error("headless_device_name_invalid"));
                }
            }
            HeadlessOperation::Connect { hold_seconds, .. }
                if !(1..=MAX_HOLD_SECONDS).contains(hold_seconds) =>
            {
                return Err(headless_error("headless_hold_invalid"));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "method",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum HeadlessOperation {
    Setup {
        setup_code: HeadlessSetupCode,
        device_name: String,
    },
    Status {},
    Refresh {},
    Probe {},
    Connect {
        selection: SelectionMode,
        proxy_mode: ProxyMode,
        refresh_first: bool,
        hold_seconds: u16,
    },
    Stop {},
    Logout {},
}

struct HeadlessSetupCode(Zeroizing<String>);

impl HeadlessSetupCode {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HeadlessSetupCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 8_192 {
            zeroize::Zeroize::zeroize(&mut value);
            return Err(serde::de::Error::custom("setup code length is invalid"));
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

struct HeadlessOutput {
    #[cfg(unix)]
    path: PathBuf,
    file: Mutex<File>,
}

impl HeadlessOutput {
    fn create(path: &Path) -> Result<Self, ClientError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(path)
            .map_err(|_| headless_error("headless_output_create_failed"))?;
        Ok(Self {
            #[cfg(unix)]
            path: path.to_path_buf(),
            file: Mutex::new(file),
        })
    }

    fn write(&self, response: &HeadlessResponse) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec_pretty(response)
            .map_err(|_| headless_error("headless_output_serialize_failed"))?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| headless_error("headless_output_unavailable"))?;
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.set_len(0))
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| headless_error("headless_output_write_failed"))?;
        #[cfg(unix)]
        {
            if let Some(parent) = self.path.parent() {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| headless_error("headless_output_write_failed"))?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeadlessResponse {
    schema_version: u16,
    complete: bool,
    outcome: HeadlessOutcome,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum HeadlessOutcome {
    Success { snapshot: Value },
    Error { code: String },
}

impl HeadlessResponse {
    fn success<T: Serialize>(complete: bool, snapshot: &T) -> Result<Self, ClientError> {
        Ok(Self {
            schema_version: HEADLESS_SCHEMA_VERSION,
            complete,
            outcome: HeadlessOutcome::Success {
                snapshot: serde_json::to_value(snapshot)
                    .map_err(|_| headless_error("headless_output_serialize_failed"))?,
            },
        })
    }

    fn error(error: &ClientError) -> Self {
        Self {
            schema_version: HEADLESS_SCHEMA_VERSION,
            complete: true,
            outcome: HeadlessOutcome::Error {
                code: error.code.clone(),
            },
        }
    }
}

pub async fn execute(app: AppHandle, invocation: HeadlessInvocation) {
    let operation = invocation.request.operation;
    let output = invocation.output;
    let result = execute_operation(&app, operation).await;
    match result {
        Ok(HeadlessExecution::Complete(snapshot)) => {
            let response = HeadlessResponse::success(true, &snapshot);
            let exit = response.and_then(|value| output.write(&value)).is_err();
            app.exit(i32::from(exit));
        }
        Ok(HeadlessExecution::Hold { snapshot, duration }) => {
            let ready = HeadlessResponse::success(false, snapshot.as_ref());
            if ready.and_then(|value| output.write(&value)).is_err() {
                app.exit(1);
                return;
            }
            tokio::time::sleep(duration).await;
            let runtime = app.state::<ConnectRuntimeRegistry>();
            match runtime.stop().await {
                Ok(stopped) => {
                    let response = HeadlessResponse::success(true, &stopped);
                    let exit = response.and_then(|value| output.write(&value)).is_err();
                    app.exit(i32::from(exit));
                }
                Err(error) => {
                    let _ = output.write(&HeadlessResponse::error(&error));
                    app.exit(1);
                }
            }
        }
        Err(error) => {
            let _ = output.write(&HeadlessResponse::error(&error));
            app.exit(1);
        }
    }
}

enum HeadlessExecution {
    Complete(Value),
    Hold {
        snapshot: Box<ConnectSnapshot>,
        duration: Duration,
    },
}

async fn execute_operation(
    app: &AppHandle,
    operation: HeadlessOperation,
) -> Result<HeadlessExecution, ClientError> {
    let runtime = app.state::<ConnectRuntimeRegistry>();
    let snapshot = match operation {
        HeadlessOperation::Setup {
            setup_code,
            device_name,
        } => {
            let setups = app.state::<SetupSessionStore>();
            let session = setups.begin(setup_code.expose())?;
            runtime
                .confirm_setup(
                    &setups,
                    session.session_id,
                    DeviceMetadata {
                        display_name: device_name,
                        client_version: env!("CARGO_PKG_VERSION").to_string(),
                        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                    },
                )
                .await?
        }
        HeadlessOperation::Status {} => {
            return runtime
                .snapshot()
                .await
                .and_then(|value| {
                    serde_json::to_value(value)
                        .map_err(|_| headless_error("headless_output_serialize_failed"))
                })
                .map(HeadlessExecution::Complete);
        }
        HeadlessOperation::Refresh {} => runtime.refresh_bundle(app).await?,
        HeadlessOperation::Probe {} => runtime.probe_nodes().await?,
        HeadlessOperation::Connect {
            selection,
            proxy_mode,
            refresh_first,
            hold_seconds,
        } => {
            if refresh_first {
                runtime.refresh_bundle(app).await?;
            }
            runtime.probe_nodes().await?;
            runtime.set_selection(selection).await?;
            let snapshot = runtime.connect(app, proxy_mode).await?;
            return Ok(HeadlessExecution::Hold {
                snapshot: Box::new(snapshot),
                duration: Duration::from_secs(u64::from(hold_seconds)),
            });
        }
        HeadlessOperation::Stop {} => runtime.stop().await?,
        HeadlessOperation::Logout {} => runtime.logout().await?,
    };
    serde_json::to_value(snapshot)
        .map_err(|_| headless_error("headless_output_serialize_failed"))
        .map(HeadlessExecution::Complete)
}

fn headless_error(code: &str) -> ClientError {
    ClientError::internal(code, "The headless operation could not be completed.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_closed_bounded_and_secret_debug_is_unavailable() {
        let valid = br#"{"schemaVersion":1,"operation":{"method":"setup","setupCode":"secret-code","deviceName":"Test device"}}"#;
        let request: HeadlessRequest = serde_json::from_slice(valid).unwrap();
        request.validate().unwrap();
        assert!(serde_json::from_slice::<HeadlessRequest>(
            br#"{"schemaVersion":1,"operation":{"method":"status","extra":true}}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<HeadlessRequest>(
            br#"{"schemaVersion":1,"operation":{"method":"connect","selection":{"kind":"automatic"},"proxyMode":"manual","refreshFirst":false,"holdSeconds":0}}"#
        )
        .unwrap()
        .validate()
        .is_err());
    }

    #[test]
    fn output_is_create_new_owner_only_and_rewriteable() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("result.json");
        let output = HeadlessOutput::create(&path).unwrap();
        output
            .write(&HeadlessResponse::success(true, &serde_json::json!({"ok": true})).unwrap())
            .unwrap();
        assert!(HeadlessOutput::create(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
