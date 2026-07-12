use crate::local_api::{
    LocalApiMethod, LocalApiRequest, LocalApiResponse, LocalServiceStatus,
    LOCAL_API_REQUEST_MAX_BYTES, LOCAL_API_RESPONSE_MAX_BYTES, LOCAL_API_SCHEMA_VERSION,
    LOCAL_API_SOCKET_FILE,
};
use anyhow::{bail, Context as _, Result};
use nix::unistd::{getpeereid, Uid};
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{oneshot, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_CONNECTIONS: usize = 8;

#[derive(Debug)]
pub(crate) struct LocalStatusServer {
    status: watch::Sender<LocalServiceStatus>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl LocalStatusServer {
    pub(crate) fn start(data_dir: &Path, initial: LocalServiceStatus) -> Result<Self> {
        initial.validate()?;
        let uid = Uid::effective().as_raw();
        validate_data_dir(data_dir, uid)?;
        let socket_path = data_dir.join(LOCAL_API_SOCKET_FILE);
        remove_stale_socket(&socket_path, uid)?;
        let listener = UnixListener::bind(&socket_path).with_context(|| {
            format!(
                "failed to bind local status socket {}",
                socket_path.display()
            )
        })?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        inspect_socket(&socket_path, uid, true)?;

        let guard = SocketPathGuard {
            path: socket_path,
            uid,
        };
        let (status, status_rx) = watch::channel(initial);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(serve(listener, guard, status_rx, shutdown_rx));
        Ok(Self {
            status,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    pub(crate) fn publish(&self, status: LocalServiceStatus) -> Result<()> {
        status.validate()?;
        if self.task.as_ref().is_none_or(JoinHandle::is_finished) {
            bail!("local status server is not running");
        }
        self.status.send_replace(status);
        Ok(())
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        if let Ok(joined) = timeout(SHUTDOWN_TIMEOUT, &mut task).await {
            joined.context("local status server task failed")??;
        } else {
            task.abort();
            let _ = task.await;
            bail!("local status server shutdown timed out");
        }
        Ok(())
    }
}

impl Drop for LocalStatusServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub(crate) async fn query(data_dir: &Path) -> Result<LocalServiceStatus> {
    let uid = Uid::effective().as_raw();
    validate_data_dir(data_dir, uid)?;
    let socket_path = data_dir.join(LOCAL_API_SOCKET_FILE);
    inspect_socket(&socket_path, uid, true)?;
    let mut stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(&socket_path))
        .await
        .context("local status connection timed out")?
        .context("Node Host local status service is unavailable")?;
    verify_peer(&stream, uid)?;

    let request = LocalApiRequest::status();
    let request_body =
        serde_json::to_vec(&request).context("failed to encode local status request")?;
    write_frame(&mut stream, &request_body, LOCAL_API_REQUEST_MAX_BYTES).await?;
    let response_body = read_frame(&mut stream, LOCAL_API_RESPONSE_MAX_BYTES).await?;
    let response: LocalApiResponse =
        serde_json::from_slice(&response_body).context("local status response is invalid")?;
    if response.schema_version != LOCAL_API_SCHEMA_VERSION {
        bail!("local status response uses an unsupported schema");
    }
    if response.request_id != request.request_id {
        bail!("local status response is not bound to this request");
    }
    response.status.validate()?;
    Ok(response.status)
}

async fn serve(
    listener: UnixListener,
    _guard: SocketPathGuard,
    status: watch::Receiver<LocalServiceStatus>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if joined.is_some_and(|result| result.is_err()) {
                    tracing::warn!("local status connection task terminated unexpectedly");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("local status socket accept failed")?;
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    continue;
                };
                let status = status.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = handle_connection(stream, status).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    status: watch::Receiver<LocalServiceStatus>,
) -> Result<()> {
    verify_peer(&stream, Uid::effective().as_raw())?;
    let request_body = read_frame(&mut stream, LOCAL_API_REQUEST_MAX_BYTES).await?;
    let request: LocalApiRequest =
        serde_json::from_slice(&request_body).context("local status request is invalid")?;
    if request.schema_version != LOCAL_API_SCHEMA_VERSION {
        bail!("unsupported local status request schema");
    }
    if request.method != LocalApiMethod::Status {
        bail!("unsupported local status method");
    }
    let response = LocalApiResponse {
        schema_version: LOCAL_API_SCHEMA_VERSION,
        request_id: request.request_id,
        status: status.borrow().clone(),
    };
    let response_body =
        serde_json::to_vec(&response).context("failed to encode local status response")?;
    write_frame(&mut stream, &response_body, LOCAL_API_RESPONSE_MAX_BYTES).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_frame(stream: &mut UnixStream, max_bytes: usize) -> Result<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    timeout(IO_TIMEOUT, stream.read_exact(&mut prefix))
        .await
        .context("local status frame prefix timed out")?
        .context("failed to read local status frame prefix")?;
    let length = usize::try_from(u32::from_be_bytes(prefix))?;
    if length == 0 || length > max_bytes {
        bail!("local status frame length is invalid");
    }
    let mut body = vec![0_u8; length];
    timeout(IO_TIMEOUT, stream.read_exact(&mut body))
        .await
        .context("local status frame body timed out")?
        .context("failed to read local status frame body")?;
    Ok(body)
}

async fn write_frame(stream: &mut UnixStream, body: &[u8], max_bytes: usize) -> Result<()> {
    if body.is_empty() || body.len() > max_bytes {
        bail!("local status response length is invalid");
    }
    let length = u32::try_from(body.len()).context("local status frame is too large")?;
    timeout(IO_TIMEOUT, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await
    })
    .await
    .context("local status frame write timed out")?
    .context("failed to write local status frame")
}

fn verify_peer(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    let (peer_uid, _) = getpeereid(stream).context("failed to authenticate local status peer")?;
    if peer_uid.as_raw() != expected_uid {
        bail!("local status peer is not the service owner");
    }
    Ok(())
}

fn validate_data_dir(data_dir: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(data_dir).with_context(|| {
        format!(
            "failed to inspect Node Host data directory {}",
            data_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("Node Host local status requires an owner-only real data directory");
    }
    Ok(())
}

fn inspect_socket(path: &Path, uid: u32, required: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != uid
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("Node Host local status socket ownership is unsafe");
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(error).context("Node Host local status socket is unavailable")
        }
        Err(error) => Err(error).context("failed to inspect Node Host local status socket"),
    }
}

fn remove_stale_socket(path: &Path, uid: u32) -> Result<()> {
    if inspect_socket(path, uid, false)? {
        fs::remove_file(path).context("failed to remove stale Node Host local status socket")?;
    }
    Ok(())
}

struct SocketPathGuard {
    path: PathBuf,
    uid: u32,
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        if inspect_socket(&self.path, self.uid, false).unwrap_or(false) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_api::{LocalServicePhase, NodeSetupPhase, LOCAL_API_SOCKET_FILE};
    use crate::{
        AdmissionCounters, ManualEndpointStatus, ProviderAvailability, ProviderMonthUsage,
        ProviderPolicy, ProviderPolicyStatus, RelayAssignmentState, RelayAssignmentStatus,
        RelayRuntimeState,
    };
    use crate::{RouterMappingState, RouterMappingStatus};
    use control_protocol::id::{
        ControllerInstanceId, EndpointId, NodeId, Revision, SequenceNumber, SigningKeyId, Timestamp,
    };
    use control_protocol::node::{
        EndpointReadiness, NodeEndpointStatus, NodeHeartbeatStatus, NodeLifecycleState,
        NodeRuntimeState,
    };
    use std::os::unix::fs::symlink;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn fixture_status() -> LocalServiceStatus {
        let node_id = NodeId::new();
        let observed_at = Timestamp::from_datetime(OffsetDateTime::now_utc());
        LocalServiceStatus {
            schema_version: LOCAL_API_SCHEMA_VERSION,
            service_instance_id: Uuid::new_v4(),
            observed_at,
            phase: LocalServicePhase::Idle,
            node_id,
            runtime_state: NodeRuntimeState::Idle,
            last_heartbeat_at: None,
            controller_status: Some(NodeHeartbeatStatus {
                schema_version: 1,
                node_id,
                heartbeat_generation: SequenceNumber::new(1).unwrap(),
                observed_at: Timestamp::from_datetime(OffsetDateTime::now_utc()),
                lifecycle: NodeLifecycleState::Pending,
                endpoints: Vec::new(),
                signing_key_id: SigningKeyId::new(),
                controller_instance_id: ControllerInstanceId::new(),
            }),
            last_sync_at: None,
            desired_revision_cursor: 0,
            applied_revision: None,
            activation_phase: None,
            xray_configured: true,
            router_mapping: RouterMappingStatus {
                enabled: false,
                state: RouterMappingState::Disabled,
                source: None,
                external_address: None,
                external_port: None,
                lease_expires_at: None,
                last_error_code: None,
            },
            provider_policy: ProviderPolicyStatus {
                policy: ProviderPolicy::default(),
                generation: 1,
                updated_at: observed_at,
                availability: ProviderAvailability::Available,
                month_usage: ProviderMonthUsage {
                    utc_month: "2026-07".to_string(),
                    observed_bytes: 0,
                    cap_bytes: Some(100 * 1024 * 1024 * 1024),
                    remaining_bytes: Some(100 * 1024 * 1024 * 1024),
                    coverage: "xrayObservedLowerBound".to_string(),
                    last_observed_at: None,
                },
                manual_endpoint: ManualEndpointStatus {
                    configured: false,
                    current: false,
                    applied_revision: None,
                    expires_at: None,
                },
            },
            admission: AdmissionCounters::default(),
            relay_assignment: RelayAssignmentStatus {
                state: RelayAssignmentState::NotConfigured,
                endpoint_id: None,
                public_address: None,
                public_port: None,
                expires_at: None,
                consented_at: None,
            },
            relay_runtime: RelayRuntimeState::NotConfigured,
            last_error: None,
        }
    }

    #[test]
    fn setup_phase_requires_controller_and_protocol_verification_evidence() {
        let mut status = fixture_status();
        assert_eq!(status.setup_phase(), NodeSetupPhase::WaitingForApproval);

        status.controller_status.as_mut().unwrap().lifecycle = NodeLifecycleState::Active;
        assert_eq!(
            status.setup_phase(),
            NodeSetupPhase::WaitingForConfiguration
        );

        status.desired_revision_cursor = 1;
        assert_eq!(status.setup_phase(), NodeSetupPhase::ApplyingConfiguration);

        status.applied_revision = Some(Revision::new(1).unwrap());
        status.phase = LocalServicePhase::Serving;
        status.runtime_state = NodeRuntimeState::Serving;
        assert_eq!(
            status.setup_phase(),
            NodeSetupPhase::EstablishingReachability
        );

        status
            .controller_status
            .as_mut()
            .unwrap()
            .endpoints
            .push(NodeEndpointStatus {
                endpoint_id: EndpointId::new(),
                readiness: EndpointReadiness::TcpReachable,
                last_checked_at: Some(Timestamp::from_datetime(OffsetDateTime::now_utc())),
                error_code: None,
            });
        assert_eq!(status.setup_phase(), NodeSetupPhase::WaitingForVerification);

        status.controller_status.as_mut().unwrap().endpoints[0].readiness =
            EndpointReadiness::Verified;
        assert_eq!(status.setup_phase(), NodeSetupPhase::Ready);
    }

    #[tokio::test]
    async fn same_user_query_returns_the_latest_bounded_status() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut expected = fixture_status();
        let server = LocalStatusServer::start(temp.path(), expected.clone()).unwrap();
        let socket = temp.path().join(LOCAL_API_SOCKET_FILE);
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(query(temp.path()).await.unwrap(), expected);

        expected.phase = LocalServicePhase::Serving;
        expected.runtime_state = NodeRuntimeState::Serving;
        server.publish(expected.clone()).unwrap();
        assert_eq!(query(temp.path()).await.unwrap(), expected);
        server.shutdown().await.unwrap();
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn oversized_request_is_dropped_without_stopping_the_server() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let expected = fixture_status();
        let server = LocalStatusServer::start(temp.path(), expected.clone()).unwrap();
        let mut stream = UnixStream::connect(temp.path().join(LOCAL_API_SOCKET_FILE))
            .await
            .unwrap();
        stream
            .write_all(
                &u32::try_from(LOCAL_API_REQUEST_MAX_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(query(temp.path()).await.unwrap(), expected);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stale_symlink_is_never_removed_or_replaced() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let socket = temp.path().join(LOCAL_API_SOCKET_FILE);
        symlink(&target, &socket).unwrap();
        let error = LocalStatusServer::start(temp.path(), fixture_status()).unwrap_err();
        assert!(error.to_string().contains("ownership is unsafe"));
        assert_eq!(fs::read(target).unwrap(), b"keep");
        assert!(fs::symlink_metadata(socket)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
