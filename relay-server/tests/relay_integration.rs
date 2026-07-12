use std::{sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use control_protocol::{
    crypto::{ed25519_signing_key_id, Ed25519PublicKey, Ed25519Signature, Sha256Digest},
    id::{
        EndpointId, NetworkId, NodeId, RelayGeneration, RelayGrantId, RelayId, RelayRouteId,
        Timestamp,
    },
    relay::{
        relay_route_transcript, relay_token_digest, RelayAssignmentHeader, RelayLimits,
        SignedRelayRoute, RELAY_SCHEMA_VERSION,
    },
};
use ed25519_dalek::{Signer as _, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use relay_server::{
    frame::{Frame, FrameKind},
    ConnectorStatus, ManagedRoutesConfig, NodeConnectorConfig, RelayConfig, RelayHandle,
    RelayNodeConnector, RelayServer, RouteConfig, ServerConfig,
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
            managed_routes: None,
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
                monthly_byte_limit: None,
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
        self.connect_node_route(handle, ROUTE_ID, token).await
    }

    async fn connect_node_route(
        &self,
        handle: &RelayHandle,
        route_id: &str,
        token: &[u8],
    ) -> TlsStream<TcpStream> {
        let socket = TcpStream::connect(handle.node_address()).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap().to_owned();
        let mut tls = TlsConnector::from(self.client_config.clone())
            .connect(name, socket)
            .await
            .unwrap();
        Frame::register(route_id, token)
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
#[allow(clippy::too_many_lines)] // One lifecycle test keeps rotate, LKG retention, and revocation in order.
async fn managed_route_watcher_rotates_rejects_invalid_update_and_revokes_removal() {
    const TOKEN_ONE: &[u8] = b"managed-route-token-one-32-bytes";
    const TOKEN_TWO: &[u8] = b"managed-route-token-two-32-bytes";

    let fixture = Fixture::new();
    let managed_directory = fixture.directory.path().join("managed-routes");
    std::fs::create_dir(&managed_directory).unwrap();
    set_owner_only_directory(&managed_directory);
    let quota_directory = fixture.directory.path().join("managed-quota");
    std::fs::create_dir(&quota_directory).unwrap();
    set_owner_only_directory(&quota_directory);

    let reserved_first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_public_port = reserved_first.local_addr().unwrap().port();
    let reserved_second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second_public_port = reserved_second.local_addr().unwrap().port();
    drop((reserved_first, reserved_second));

    let signing_key = SigningKey::from_bytes(&[21; 32]);
    let controller_public_key = public_key(&signing_key);
    let relay_id = RelayId::new();
    let route_id = RelayRouteId::new();
    let certificate_digest = Sha256Digest::from_bytes(
        hex::decode(&fixture.config.routes[0].node_cert_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let mut config = fixture.config.clone();
    config.routes.clear();
    config.server.reload_interval_secs = 1;
    // This test deliberately leaves its test tunnels idle while verifying LKG reload behavior.
    config.server.heartbeat_interval_secs = 5;
    config.server.heartbeat_timeout_secs = 10;
    config.managed_routes = Some(ManagedRoutesConfig {
        relay_id,
        managed_routes_directory: managed_directory.clone(),
        quota_state_directory: quota_directory,
        controller_public_key,
        public_listen_ip: "127.0.0.1".parse().unwrap(),
        public_port_start: first_public_port.min(second_public_port),
        public_port_end: first_public_port.max(second_public_port),
        max_concurrent_streams: 4,
        max_bytes_per_second: 2_000_000,
        max_bytes_per_connection: 4_000_000,
        monthly_byte_limit: 8_000_000,
    });

    let first = signed_managed_route(
        &signing_key,
        relay_id,
        route_id,
        1,
        first_public_port,
        relay_token_digest(TOKEN_ONE),
        certificate_digest.clone(),
    );
    let first_registration_id = first.header.grant_id.to_string();
    let route_path = write_managed_route(&managed_directory, &first);
    let handle = RelayServer::start(config).await.unwrap();
    assert_eq!(
        handle
            .route_address(&first_registration_id)
            .await
            .unwrap()
            .port(),
        first_public_port
    );

    let mut first_node = fixture
        .connect_node_route(&handle, &first_registration_id, TOKEN_ONE)
        .await;
    assert_eq!(
        read_frame(&mut first_node).await.kind,
        FrameKind::RegisterOk
    );

    let second = signed_managed_route(
        &signing_key,
        relay_id,
        route_id,
        2,
        second_public_port,
        relay_token_digest(TOKEN_TWO),
        certificate_digest,
    );
    let second_registration_id = second.header.grant_id.to_string();
    let second_route_path = write_managed_route(&managed_directory, &second);
    wait_for_route_present(&handle, &second_registration_id).await;

    let mut second_node = fixture
        .connect_node_route(&handle, &second_registration_id, TOKEN_TWO)
        .await;
    assert_eq!(
        read_frame(&mut second_node).await.kind,
        FrameKind::RegisterOk
    );
    let mut predecessor_still_valid = fixture
        .connect_node_route(&handle, &first_registration_id, TOKEN_ONE)
        .await;
    assert_eq!(
        read_frame(&mut predecessor_still_valid).await.kind,
        FrameKind::RegisterOk
    );

    std::fs::remove_file(&route_path).unwrap();
    wait_for_route_absent(&handle, &first_registration_id).await;
    let predecessor_closed = tokio::time::timeout(
        Duration::from_secs(2),
        Frame::read_from(&mut predecessor_still_valid, MAX_FRAME_BYTES),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(predecessor_closed.is_none());

    std::fs::write(&second_route_path, b"{").unwrap();
    set_owner_only(&second_route_path);
    tokio::time::sleep(Duration::from_millis(1_250)).await;
    let mut lkg_node = fixture
        .connect_node_route(&handle, &second_registration_id, TOKEN_TWO)
        .await;
    assert_eq!(read_frame(&mut lkg_node).await.kind, FrameKind::RegisterOk);

    std::fs::remove_file(second_route_path).unwrap();
    wait_for_route_absent(&handle, &second_registration_id).await;
    let closed = tokio::time::timeout(
        Duration::from_secs(2),
        Frame::read_from(&mut lkg_node, MAX_FRAME_BYTES),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(closed.is_none());
    handle.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Exercises one real bidirectional stream through the durable managed cap.
async fn managed_monthly_cap_truncates_at_exact_bidirectional_boundary_and_refuses_next_stream() {
    const MONTHLY_LIMIT: usize = 1_048_576;
    const UPLOAD_BYTES: usize = 600 * 1_024;

    let fixture = Fixture::new();
    let managed_directory = fixture.directory.path().join("quota-route-registry");
    let quota_directory = fixture.directory.path().join("quota-state");
    std::fs::create_dir(&managed_directory).unwrap();
    std::fs::create_dir(&quota_directory).unwrap();
    set_owner_only_directory(&managed_directory);
    set_owner_only_directory(&quota_directory);

    let reserved_public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_port = reserved_public.local_addr().unwrap().port();
    drop(reserved_public);
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let relay_id = RelayId::new();
    let certificate_digest = Sha256Digest::from_bytes(
        hex::decode(&fixture.config.routes[0].node_cert_sha256)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let mut route = signed_managed_route(
        &signing_key,
        relay_id,
        RelayRouteId::new(),
        1,
        public_port,
        relay_token_digest(ROUTE_TOKEN),
        certificate_digest,
    );
    route.header.limits.monthly_byte_limit = u64::try_from(MONTHLY_LIMIT).unwrap();
    sign_route(&mut route, &signing_key);
    let registration_id = route.header.grant_id.to_string();
    write_managed_route(&managed_directory, &route);

    let mut config = fixture.config.clone();
    config.routes.clear();
    config.managed_routes = Some(ManagedRoutesConfig {
        relay_id,
        managed_routes_directory: managed_directory,
        quota_state_directory: quota_directory,
        controller_public_key: public_key(&signing_key),
        public_listen_ip: "127.0.0.1".parse().unwrap(),
        public_port_start: public_port,
        public_port_end: public_port,
        max_concurrent_streams: 4,
        max_bytes_per_second: 2_000_000,
        max_bytes_per_connection: 4_000_000,
        monthly_byte_limit: 2_000_000,
    });
    let handle = RelayServer::start(config).await.unwrap();

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut upload = Vec::new();
        stream.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload.len(), UPLOAD_BYTES);
        let _ = stream.write_all(&upload).await;
        let _ = stream.shutdown().await;
    });
    let mut connector_config = fixture.connector_config(handle.node_address(), target_address);
    connector_config.route_id.clone_from(&registration_id);
    let connector = Arc::new(RelayNodeConnector::new(connector_config).await.unwrap());
    let mut status = connector.subscribe();
    let connector_shutdown = CancellationToken::new();
    let task_connector = connector.clone();
    let task_shutdown = connector_shutdown.clone();
    let connector_task = tokio::spawn(async move { task_connector.run(task_shutdown).await });
    wait_for_status(&mut status, |value| value == &ConnectorStatus::Registered).await;

    let route_address = handle.route_address(&registration_id).await.unwrap();
    let mut member = TcpStream::connect(route_address).await.unwrap();
    member.write_all(&vec![0x5a; UPLOAD_BYTES]).await.unwrap();
    member.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), member.read_to_end(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed.len(), MONTHLY_LIMIT - UPLOAD_BYTES);
    assert!(echoed.iter().all(|byte| *byte == 0x5a));

    let mut refused = TcpStream::connect(route_address).await.unwrap();
    let mut refused_payload = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        refused.read_to_end(&mut refused_payload),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(refused_payload.is_empty());

    connector_shutdown.cancel();
    connector_task.await.unwrap();
    handle.shutdown().await;
    target_task.await.unwrap();
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

fn signed_managed_route(
    signing_key: &SigningKey,
    relay_id: RelayId,
    route_id: RelayRouteId,
    generation: i64,
    public_port: u16,
    route_token_sha256: Sha256Digest,
    client_certificate_sha256: Sha256Digest,
) -> SignedRelayRoute {
    let now = OffsetDateTime::now_utc();
    let issued_at = now - time::Duration::minutes(1);
    let controller_public_key = public_key(signing_key);
    let mut route = SignedRelayRoute {
        header: RelayAssignmentHeader {
            schema_version: RELAY_SCHEMA_VERSION,
            network_id: NetworkId::new(),
            node_id: NodeId::new(),
            relay_id,
            route_id,
            grant_id: RelayGrantId::new(),
            generation: RelayGeneration::new(generation).unwrap(),
            endpoint_id: EndpointId::new(),
            public_host: "relay.example.test".to_owned(),
            public_port,
            tunnel_host: "relay.example.test".to_owned(),
            tunnel_port: 7_443,
            tls_server_name: "relay.example.test".to_owned(),
            issued_at: Timestamp::from_datetime(issued_at),
            not_before: Timestamp::from_datetime(issued_at),
            expires_at: Timestamp::from_datetime(now + time::Duration::hours(1)),
            limits: RelayLimits {
                max_concurrent_streams: 2,
                max_bytes_per_second: 1_000_000,
                max_bytes_per_connection: 2_000_000,
                monthly_byte_limit: 4_000_000,
            },
        },
        route_token_sha256,
        client_certificate_sha256,
        signing_key_id: ed25519_signing_key_id(&controller_public_key).unwrap(),
        signature: URL_SAFE_NO_PAD.encode([0; 64]).parse().unwrap(),
    };
    sign_route(&mut route, signing_key);
    route
}

fn sign_route(route: &mut SignedRelayRoute, signing_key: &SigningKey) {
    let signature = signing_key.sign(&relay_route_transcript(route).unwrap());
    route.signature = URL_SAFE_NO_PAD
        .encode(signature.to_bytes())
        .parse::<Ed25519Signature>()
        .unwrap();
}

fn public_key(signing_key: &SigningKey) -> Ed25519PublicKey {
    URL_SAFE_NO_PAD
        .encode(signing_key.verifying_key().to_bytes())
        .parse()
        .unwrap()
}

fn write_managed_route(
    directory: &std::path::Path,
    route: &SignedRelayRoute,
) -> std::path::PathBuf {
    let temporary = directory.parent().unwrap().join("managed-route-next");
    std::fs::write(&temporary, serde_json::to_vec(route).unwrap()).unwrap();
    set_owner_only(&temporary);
    let destination = directory.join(format!("{}.relay-route.json", route.header.grant_id));
    std::fs::rename(temporary, &destination).unwrap();
    destination
}

async fn wait_for_route_absent(handle: &RelayHandle, route_id: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while handle.route_address(route_id).await.is_some() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_route_present(handle: &RelayHandle, route_id: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handle.route_address(route_id).await.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
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

#[cfg(unix)]
fn set_owner_only_directory(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &std::path::Path) {}
