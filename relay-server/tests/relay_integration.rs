use std::{sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use relay_server::{
    frame::{Frame, FrameKind},
    ConnectorStatus, NodeConnectorConfig, RelayConfig, RelayHandle, RelayNodeConnector,
    RelayServer, RouteConfig, ServerConfig,
};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_util::sync::CancellationToken;

const ROUTE_ID: &str = "route_0123456789abcdef";
const ROUTE_TOKEN: &[u8] = b"test-route-token-with-256-bits-000";
const MAX_FRAME_BYTES: usize = 1_024;

struct Fixture {
    directory: TempDir,
    config: RelayConfig,
    client_config: Arc<ClientConfig>,
    client_cert_path: std::path::PathBuf,
    client_key_path: std::path::PathBuf,
    route_token_path: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap();

        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &ca).unwrap();

        let server_cert_path = directory.path().join("server.pem");
        let server_key_path = directory.path().join("server-key.pem");
        let ca_path = directory.path().join("ca.pem");
        let client_cert_path = directory.path().join("node.pem");
        let client_key_path = directory.path().join("node-key.pem");
        let route_token_path = directory.path().join("route-token");
        std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
        std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca.pem()).unwrap();
        std::fs::write(&client_cert_path, client_cert.pem()).unwrap();
        std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
        std::fs::write(&route_token_path, ROUTE_TOKEN).unwrap();
        set_owner_only(&server_key_path);
        set_owner_only(&client_key_path);
        set_owner_only(&route_token_path);

        let token_digest = hex::encode(Sha256::digest(ROUTE_TOKEN));
        let cert_digest = hex::encode(Sha256::digest(client_cert.der().as_ref()));
        let config = RelayConfig {
            server: ServerConfig {
                node_listen: "127.0.0.1:0".parse().unwrap(),
                metrics_listen: "127.0.0.1:0".parse().unwrap(),
                tls_cert_path: server_cert_path,
                tls_key_path: server_key_path,
                client_ca_path: ca_path,
                max_frame_bytes: MAX_FRAME_BYTES,
                command_queue_frames: 16,
                stream_buffer_frames: 4,
                initial_window_bytes: 4_096,
                open_timeout_secs: 2,
                no_payload_timeout_secs: 2,
                idle_timeout_secs: 5,
                heartbeat_interval_secs: 1,
                heartbeat_timeout_secs: 3,
                reload_interval_secs: 1,
                max_routes: 4,
                max_node_connections: 4,
            },
            routes: vec![RouteConfig {
                route_id: ROUTE_ID.to_owned(),
                public_listen: "127.0.0.1:0".parse().unwrap(),
                node_token_sha256: token_digest,
                node_cert_sha256: cert_digest,
                expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
                enabled: true,
                max_concurrent_streams: 2,
                max_bytes_per_second: 1_000_000,
                max_bytes_per_connection: 1_000_000,
            }],
        };

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let key: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(client_key.serialize_der()).into();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_cert.der().clone()], key)
            .unwrap();
        client_config.alpn_protocols = vec![b"pn-relay-v1".to_vec()];

        Self {
            directory,
            config,
            client_config: Arc::new(client_config),
            client_cert_path,
            client_key_path,
            route_token_path,
        }
    }

    async fn start(&self) -> RelayHandle {
        debug_assert!(self.directory.path().exists());
        RelayServer::start(self.config.clone()).await.unwrap()
    }

    async fn connect_node(&self, handle: &RelayHandle, token: &[u8]) -> TlsStream<TcpStream> {
        let socket = TcpStream::connect(handle.node_address()).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap().to_owned();
        let mut tls = TlsConnector::from(self.client_config.clone())
            .connect(name, socket)
            .await
            .unwrap();
        Frame::register(ROUTE_ID, token)
            .unwrap()
            .write_to(&mut tls, MAX_FRAME_BYTES)
            .await
            .unwrap();
        tls
    }

    fn connector_config(
        &self,
        relay_address: std::net::SocketAddr,
        local_target: std::net::SocketAddr,
    ) -> NodeConnectorConfig {
        NodeConnectorConfig {
            relay_address,
            relay_server_name: "localhost".to_owned(),
            route_id: ROUTE_ID.to_owned(),
            route_token_path: self.route_token_path.clone(),
            tls_cert_path: self.client_cert_path.clone(),
            tls_key_path: self.client_key_path.clone(),
            relay_ca_path: self.config.server.client_ca_path.clone(),
            local_target,
            max_frame_bytes: MAX_FRAME_BYTES,
            command_queue_frames: 16,
            stream_buffer_frames: 4,
            initial_window_bytes: 4_096,
            max_streams: 2,
            connect_timeout_secs: 1,
            idle_timeout_secs: 5,
            heartbeat_interval_secs: 1,
            heartbeat_timeout_secs: 3,
            reconnect_initial_ms: 25,
            reconnect_max_secs: 1,
        }
    }
}

#[tokio::test]
async fn forwards_unmodified_bytes_in_both_directions_with_half_close() {
    let fixture = Fixture::new();
    let handle = fixture.start().await;
    let mut node = fixture.connect_node(&handle, ROUTE_TOKEN).await;
    let registered = read_frame(&mut node).await;
    assert_eq!(registered.kind, FrameKind::RegisterOk);

    let route_address = handle.route_address(ROUTE_ID).await.unwrap();
    let mut member = TcpStream::connect(route_address).await.unwrap();
    let open = read_frame(&mut node).await;
    assert_eq!(open.kind, FrameKind::Open);
    assert_eq!(open.parse_u32().unwrap(), 4_096);
    Frame::u32(FrameKind::OpenOk, open.stream_id, 4_096)
        .write_to(&mut node, MAX_FRAME_BYTES)
        .await
        .unwrap();

    let member_payload = b"opaque-vless-reality-client-hello";
    member.write_all(member_payload).await.unwrap();
    member.shutdown().await.unwrap();
    let upload = read_kind(&mut node, FrameKind::Data).await;
    assert_eq!(upload.stream_id, open.stream_id);
    assert_eq!(upload.payload, member_payload);
    let fin = read_kind(&mut node, FrameKind::Fin).await;
    assert_eq!(fin.stream_id, open.stream_id);

    let node_payload = b"opaque-vless-reality-server-response";
    Frame::new(FrameKind::Data, open.stream_id, node_payload.to_vec())
        .write_to(&mut node, MAX_FRAME_BYTES)
        .await
        .unwrap();
    Frame::new(FrameKind::Fin, open.stream_id, Vec::new())
        .write_to(&mut node, MAX_FRAME_BYTES)
        .await
        .unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), member.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, node_payload);

    let rendered = handle.metrics().render();
    assert!(rendered.contains("relay_route_accepted_streams_total"));
    assert!(rendered.contains("relay_route_bytes_member_to_node_total"));
    assert!(!rendered.contains("client_ip"));
    handle.shutdown().await;
}

#[tokio::test]
async fn rejects_wrong_route_token_with_stable_error() {
    let fixture = Fixture::new();
    let handle = fixture.start().await;
    let mut node = fixture.connect_node(&handle, b"wrong-token").await;
    let error = read_frame(&mut node).await;
    assert_eq!(error.kind, FrameKind::Error);
    assert_eq!(error.payload, b"relay_auth_failed");
    handle.shutdown().await;
}

#[tokio::test]
async fn route_disable_revokes_tunnel_and_public_listener() {
    let fixture = Fixture::new();
    let handle = fixture.start().await;
    let mut node = fixture.connect_node(&handle, ROUTE_TOKEN).await;
    assert_eq!(read_frame(&mut node).await.kind, FrameKind::RegisterOk);

    let mut disabled = fixture.config.clone();
    disabled.routes[0].enabled = false;
    handle.reload(disabled).await.unwrap();
    assert!(handle.route_address(ROUTE_ID).await.is_none());
    let closed = tokio::time::timeout(
        Duration::from_secs(2),
        Frame::read_from(&mut node, MAX_FRAME_BYTES),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(closed.is_none());
    handle.shutdown().await;
}

#[tokio::test]
async fn metrics_http_surface_is_loopback_and_bounded() {
    let fixture = Fixture::new();
    let handle = fixture.start().await;
    let mut socket = TcpStream::connect(handle.metrics_address()).await.unwrap();
    socket
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("ok\n"));
    handle.shutdown().await;
}

#[tokio::test]
async fn real_connector_reconnects_and_relays_opaque_payload_to_fixed_loopback_target() {
    let fixture = Fixture::new();
    let reserved_node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_address = reserved_node_listener.local_addr().unwrap();
    drop(reserved_node_listener);

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let mut streams = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            streams.spawn(async move {
                let mut buffer = [0_u8; 1_024];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        stream.shutdown().await.unwrap();
                        return;
                    }
                    stream.write_all(&buffer[..read]).await.unwrap();
                }
            });
        }
        while let Some(result) = streams.join_next().await {
            result.unwrap();
        }
    });

    let connector = Arc::new(
        RelayNodeConnector::new(fixture.connector_config(node_address, target_address))
            .await
            .unwrap(),
    );
    let mut status = connector.subscribe();
    let connector_shutdown = CancellationToken::new();
    let task_connector = connector.clone();
    let task_shutdown = connector_shutdown.clone();
    let connector_task = tokio::spawn(async move { task_connector.run(task_shutdown).await });
    wait_for_status(&mut status, |value| {
        matches!(value, ConnectorStatus::Backoff { .. })
    })
    .await;

    let mut server_config = fixture.config.clone();
    server_config.server.node_listen = node_address;
    let handle = RelayServer::start(server_config).await.unwrap();
    wait_for_status(&mut status, |value| value == &ConnectorStatus::Registered).await;

    let route_address = handle.route_address(ROUTE_ID).await.unwrap();
    let first = member_round_trip(route_address, b"stream-one\x00\xff");
    let second = member_round_trip(route_address, b"stream-two-is-distinct\xfe");
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first, b"stream-one\x00\xff");
    assert_eq!(second, b"stream-two-is-distinct\xfe");

    connector_shutdown.cancel();
    connector_task.await.unwrap();
    assert_eq!(*status.borrow(), ConnectorStatus::Stopped);
    handle.shutdown().await;
    target_task.await.unwrap();
}

async fn member_round_trip(address: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut member = TcpStream::connect(address).await.unwrap();
    member.write_all(payload).await.unwrap();
    let mut echoed = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), member.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    member.shutdown().await.unwrap();
    echoed
}

async fn read_frame(stream: &mut TlsStream<TcpStream>) -> Frame {
    tokio::time::timeout(
        Duration::from_secs(2),
        Frame::read_from(stream, MAX_FRAME_BYTES),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap()
}

async fn read_kind(stream: &mut TlsStream<TcpStream>, expected: FrameKind) -> Frame {
    loop {
        let frame = read_frame(stream).await;
        if frame.kind == FrameKind::Ping {
            Frame::new(FrameKind::Pong, 0, frame.payload)
                .write_to(stream, MAX_FRAME_BYTES)
                .await
                .unwrap();
        } else if frame.kind == expected {
            return frame;
        }
    }
}

async fn wait_for_status(
    status: &mut tokio::sync::watch::Receiver<ConnectorStatus>,
    predicate: impl Fn(&ConnectorStatus) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if predicate(&status.borrow()) {
                return;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_owner_only(_path: &std::path::Path) {}
