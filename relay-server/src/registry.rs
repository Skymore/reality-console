use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read as _, Take},
    net::SocketAddr,
    path::Path,
};

use control_protocol::{
    crypto::ed25519_signing_key_id,
    id::RelayGrantId,
    relay::{verify_relay_route_signature, SignedRelayRoute},
};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::{
    config::{ManagedRoutesConfig, RelayConfig, RouteConfig},
    error::{RelayError, Result},
};

const MAX_ROUTE_FILE_BYTES: u64 = 64 * 1024;
const MAX_ROUTE_FILE_NAME_BYTES: usize = 255;

#[derive(Debug)]
pub(crate) struct ManagedRouteSnapshot {
    pub fingerprint: [u8; 32],
    pub routes: Vec<RouteConfig>,
}

pub(crate) async fn load_effective_routes(
    config: &RelayConfig,
    now: OffsetDateTime,
) -> Result<(Vec<RouteConfig>, Option<[u8; 32]>)> {
    let Some(managed) = config.managed_routes.clone() else {
        return Ok((config.routes.clone(), None));
    };
    let max_routes = config.server.max_routes;
    let snapshot =
        tokio::task::spawn_blocking(move || load_managed_routes(&managed, max_routes, now))
            .await
            .map_err(|_| managed_error("managed_routes_worker_failed"))??;
    let mut routes = config.routes.clone();
    validate_static_managed_listener_conflicts(&routes, &snapshot.routes)?;
    routes.extend(snapshot.routes);
    config.validate_routes(&routes)?;
    Ok((routes, Some(snapshot.fingerprint)))
}

fn load_managed_routes(
    config: &ManagedRoutesConfig,
    max_routes: usize,
    now: OffsetDateTime,
) -> Result<ManagedRouteSnapshot> {
    let directory_metadata = fs::symlink_metadata(&config.managed_routes_directory)
        .map_err(|_| managed_error("managed_routes_directory_unavailable"))?;
    if !directory_metadata.file_type().is_dir() {
        return Err(managed_error("managed_routes_directory_invalid"));
    }
    validate_directory_owner(&directory_metadata)?;

    let mut entries = fs::read_dir(&config.managed_routes_directory)
        .map_err(|_| managed_error("managed_routes_directory_unreadable"))?
        .map(|entry| {
            entry
                .map(|entry| (entry.file_name(), entry.path()))
                .map_err(|_| managed_error("managed_routes_directory_unreadable"))
        })
        .collect::<Result<Vec<_>>>()?;
    if entries.len() > max_routes {
        return Err(managed_error("managed_routes_count_exceeded"));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let expected_key_id = ed25519_signing_key_id(&config.controller_public_key)
        .map_err(|_| managed_error("managed_routes_key_invalid"))?;
    let mut fingerprint = Sha256::new();
    fingerprint.update(b"relay-managed-routes-v1");
    fingerprint.update(
        u64::try_from(entries.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    let mut routes = Vec::with_capacity(entries.len());
    let mut route_generations = HashSet::with_capacity(entries.len());
    let mut endpoint_ids = HashSet::with_capacity(entries.len());
    let mut public_ports = HashSet::with_capacity(entries.len());
    for (file_name, path) in entries {
        let file_grant_id = validate_file_name(&file_name)?;
        let bytes = read_route_file(&path, directory_owner(&directory_metadata))?;
        fingerprint.update(
            u64::try_from(file_name.as_encoded_bytes().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        fingerprint.update(file_name.as_encoded_bytes());
        fingerprint.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        fingerprint.update(&bytes);

        let signed: SignedRelayRoute = serde_json::from_slice(&bytes)
            .map_err(|_| managed_error("managed_route_json_invalid"))?;
        signed
            .validate()
            .map_err(|_| managed_error("managed_route_header_invalid"))?;
        if signed.header.grant_id != file_grant_id {
            return Err(managed_error("managed_route_filename_grant_mismatch"));
        }
        if signed.signing_key_id != expected_key_id {
            return Err(managed_error("managed_route_key_id_mismatch"));
        }
        verify_relay_route_signature(&signed, &config.controller_public_key)
            .map_err(|_| managed_error("managed_route_signature_invalid"))?;
        let active = now >= signed.header.not_before.as_datetime()
            && now < signed.header.expires_at.as_datetime();
        fingerprint.update([u8::from(active)]);
        if !active {
            continue;
        }
        let identity = (signed.header.route_id, signed.header.generation);
        if !route_generations.insert(identity) {
            return Err(managed_error("managed_route_duplicate_generation"));
        }
        if !endpoint_ids.insert(signed.header.endpoint_id) {
            return Err(managed_error("managed_route_duplicate_endpoint"));
        }
        let route = convert_route(config, signed)?;
        if !public_ports.insert(route.public_listen.port()) {
            return Err(managed_error("managed_route_duplicate_public_port"));
        }
        routes.push(route);
    }

    Ok(ManagedRouteSnapshot {
        fingerprint: fingerprint.finalize().into(),
        routes,
    })
}

fn convert_route(config: &ManagedRoutesConfig, signed: SignedRelayRoute) -> Result<RouteConfig> {
    let header = signed.header;
    if header.relay_id != config.relay_id {
        return Err(managed_error("managed_route_relay_mismatch"));
    }
    if !(config.public_port_start..=config.public_port_end).contains(&header.public_port) {
        return Err(managed_error("managed_route_port_out_of_range"));
    }
    if header.limits.max_concurrent_streams > config.max_concurrent_streams
        || header.limits.max_bytes_per_second > config.max_bytes_per_second
        || header.limits.max_bytes_per_connection > config.max_bytes_per_connection
        || header.limits.monthly_byte_limit > config.monthly_byte_limit
    {
        return Err(managed_error("managed_route_ceiling_exceeded"));
    }

    Ok(RouteConfig {
        // A grant is the exact credential generation registered by Node Host. The logical route
        // ID remains stable across rotation, while two grant IDs may coexist during cutover.
        route_id: header.grant_id.to_string(),
        public_listen: SocketAddr::new(config.public_listen_ip, header.public_port),
        node_token_sha256: digest_hex(signed.route_token_sha256.as_str())?,
        node_cert_sha256: digest_hex(signed.client_certificate_sha256.as_str())?,
        expires_at: header.expires_at.as_datetime(),
        enabled: true,
        max_concurrent_streams: usize::from(header.limits.max_concurrent_streams),
        max_bytes_per_second: header.limits.max_bytes_per_second,
        max_bytes_per_connection: header.limits.max_bytes_per_connection,
        monthly_byte_limit: Some(header.limits.monthly_byte_limit),
    })
}

fn digest_hex(value: &str) -> Result<String> {
    value
        .strip_prefix("sha256:")
        .map(ToOwned::to_owned)
        .ok_or_else(|| managed_error("managed_route_digest_invalid"))
}

fn validate_static_managed_listener_conflicts(
    static_routes: &[RouteConfig],
    managed_routes: &[RouteConfig],
) -> Result<()> {
    for static_route in static_routes {
        for managed_route in managed_routes {
            if static_route.public_listen.port() == managed_route.public_listen.port() {
                return Err(managed_error("managed_route_static_listener_conflict"));
            }
        }
    }
    Ok(())
}

#[allow(clippy::case_sensitive_file_extension_comparisons)] // The registry accepts only canonical lowercase `.json`.
fn validate_file_name(file_name: &OsString) -> Result<RelayGrantId> {
    let Some(name) = file_name.to_str() else {
        return Err(managed_error("managed_route_filename_invalid"));
    };
    let stem = name.strip_suffix(".relay-route.json").unwrap_or_default();
    if name.len() > MAX_ROUTE_FILE_NAME_BYTES {
        return Err(managed_error("managed_route_filename_invalid"));
    }
    stem.parse::<RelayGrantId>()
        .map_err(|_| managed_error("managed_route_filename_invalid"))
}

fn read_route_file(path: &Path, expected_owner: u32) -> Result<Vec<u8>> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| managed_error("managed_route_file_unavailable"))?;
    validate_file_metadata(&path_metadata, expected_owner)?;
    let file = open_no_follow(path)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| managed_error("managed_route_file_unavailable"))?;
    validate_file_metadata(&opened_metadata, expected_owner)?;
    validate_same_file(&path_metadata, &opened_metadata)?;

    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len()).unwrap_or(0));
    let mut bounded: Take<File> = file.take(MAX_ROUTE_FILE_BYTES + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| managed_error("managed_route_file_unreadable"))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ROUTE_FILE_BYTES {
        return Err(managed_error("managed_route_file_size_invalid"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| managed_error("managed_route_file_unavailable"))
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| managed_error("managed_route_file_unavailable"))
}

#[cfg(unix)]
fn validate_directory_owner(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if metadata.uid() != effective_uid() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(managed_error(
            "managed_routes_directory_permissions_invalid",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_owner(_metadata: &fs::Metadata) -> Result<()> {
    Err(managed_error("managed_routes_platform_unsupported"))
}

#[cfg(unix)]
fn directory_owner(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.uid()
}

#[cfg(not(unix))]
fn directory_owner(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn validate_file_metadata(metadata: &fs::Metadata, expected_owner: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !metadata.file_type().is_file() {
        return Err(managed_error("managed_route_file_type_invalid"));
    }
    if metadata.uid() != expected_owner || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(managed_error("managed_route_file_permissions_invalid"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ROUTE_FILE_BYTES {
        return Err(managed_error("managed_route_file_size_invalid"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_metadata(metadata: &fs::Metadata, _expected_owner: u32) -> Result<()> {
    if !metadata.file_type().is_file() {
        return Err(managed_error("managed_route_file_type_invalid"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ROUTE_FILE_BYTES {
        return Err(managed_error("managed_route_file_size_invalid"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(managed_error("managed_route_file_changed"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(_before: &fs::Metadata, _after: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn managed_error(code: &'static str) -> RelayError {
    RelayError::Config(code.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use control_protocol::{
        crypto::{ed25519_signing_key_id, Ed25519PublicKey, Ed25519Signature, Sha256Digest},
        id::{
            EndpointId, NetworkId, NodeId, RelayGeneration, RelayGrantId, RelayId, RelayRouteId,
            Timestamp,
        },
        relay::{
            relay_route_transcript, RelayAssignmentHeader, RelayLimits, SignedRelayRoute,
            RELAY_SCHEMA_VERSION,
        },
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::path::PathBuf;
    use time::Duration;

    struct Fixture {
        directory: tempfile::TempDir,
        signing_key: SigningKey,
        config: ManagedRoutesConfig,
        route_id: RelayRouteId,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            set_owner_only(directory.path(), true);
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            let controller_public_key = public_key(&signing_key);
            Self {
                config: ManagedRoutesConfig {
                    relay_id: RelayId::new(),
                    managed_routes_directory: directory.path().to_owned(),
                    quota_state_directory: directory.path().join("quota-state"),
                    controller_public_key,
                    public_listen_ip: "127.0.0.1".parse().unwrap(),
                    public_port_start: 20_000,
                    public_port_end: 21_000,
                    max_concurrent_streams: 32,
                    max_bytes_per_second: 10_000_000,
                    max_bytes_per_connection: 10_000_000,
                    monthly_byte_limit: 20_000_000,
                },
                directory,
                signing_key,
                route_id: RelayRouteId::new(),
            }
        }

        fn route(&self, generation: i64, port: u16, digest_byte: u8) -> SignedRelayRoute {
            self.route_with(self.route_id, generation, port, digest_byte, false)
        }

        fn route_with(
            &self,
            route_id: RelayRouteId,
            generation: i64,
            port: u16,
            digest_byte: u8,
            expired: bool,
        ) -> SignedRelayRoute {
            let now = OffsetDateTime::now_utc();
            let issued_at = if expired {
                now - Duration::hours(2)
            } else {
                now - Duration::minutes(1)
            };
            let expires_at = if expired {
                now - Duration::seconds(1)
            } else {
                now + Duration::hours(1)
            };
            let mut route = SignedRelayRoute {
                header: RelayAssignmentHeader {
                    schema_version: RELAY_SCHEMA_VERSION,
                    network_id: NetworkId::new(),
                    node_id: NodeId::new(),
                    relay_id: self.config.relay_id,
                    route_id,
                    grant_id: RelayGrantId::new(),
                    generation: RelayGeneration::new(generation).unwrap(),
                    endpoint_id: EndpointId::new(),
                    public_host: "relay.example.test".to_owned(),
                    public_port: port,
                    tunnel_host: "relay.example.test".to_owned(),
                    tunnel_port: 7_443,
                    tls_server_name: "relay.example.test".to_owned(),
                    issued_at: Timestamp::from_datetime(issued_at),
                    not_before: Timestamp::from_datetime(issued_at),
                    expires_at: Timestamp::from_datetime(expires_at),
                    limits: RelayLimits {
                        max_concurrent_streams: 8,
                        max_bytes_per_second: 2_000_000,
                        max_bytes_per_connection: 4_000_000,
                        monthly_byte_limit: 8_000_000,
                    },
                },
                route_token_sha256: Sha256Digest::from_bytes([digest_byte; 32]),
                client_certificate_sha256: Sha256Digest::from_bytes([9; 32]),
                signing_key_id: ed25519_signing_key_id(&self.config.controller_public_key).unwrap(),
                signature: URL_SAFE_NO_PAD.encode([0; 64]).parse().unwrap(),
            };
            sign(&mut route, &self.signing_key);
            route
        }

        fn write(&self, name: &str, route: &SignedRelayRoute) -> PathBuf {
            let path = self.directory.path().join(name);
            fs::write(&path, serde_json::to_vec(route).unwrap()).unwrap();
            set_owner_only(&path, false);
            path
        }

        fn write_route(&self, route: &SignedRelayRoute) -> PathBuf {
            self.write(
                &format!("{}.relay-route.json", route.header.grant_id),
                route,
            )
        }

        fn load(&self) -> Result<ManagedRouteSnapshot> {
            load_managed_routes(&self.config, 16, OffsetDateTime::now_utc())
        }
    }

    #[test]
    fn fingerprint_is_deterministic_for_empty_directory() {
        let fixture = Fixture::new();
        let first = fixture.load().unwrap();
        let second = fixture.load().unwrap();
        assert_eq!(first.fingerprint, second.fingerprint);
    }

    #[test]
    fn valid_add_remove_and_rotation_change_the_complete_snapshot() {
        let fixture = Fixture::new();
        let first = fixture.route(1, 20_100, 1);
        let path = fixture.write_route(&first);
        let added = fixture.load().unwrap();
        assert_eq!(added.routes.len(), 1);
        assert_eq!(added.routes[0].route_id, first.header.grant_id.to_string());
        assert_eq!(added.routes[0].node_token_sha256, hex::encode([1; 32]));

        let second = fixture.route(2, 20_101, 2);
        let second_path = fixture.write_route(&second);
        let rotated = fixture.load().unwrap();
        assert_ne!(added.fingerprint, rotated.fingerprint);
        assert_eq!(rotated.routes.len(), 2);
        assert!(rotated
            .routes
            .iter()
            .any(|route| route.route_id == second.header.grant_id.to_string()));

        fs::remove_file(path).unwrap();
        let predecessor_removed = fixture.load().unwrap();
        assert_eq!(predecessor_removed.routes.len(), 1);
        assert_eq!(
            predecessor_removed.routes[0].route_id,
            second.header.grant_id.to_string()
        );
        fs::remove_file(second_path).unwrap();
        assert!(fixture.load().unwrap().routes.is_empty());
    }

    #[test]
    fn rejects_tamper_wrong_key_and_expired_route() {
        let fixture = Fixture::new();
        let mut tampered = fixture.route(1, 20_100, 1);
        tampered.header.public_port = 20_101;
        let path = fixture.write_route(&tampered);
        assert!(fixture.load().is_err());

        fs::remove_file(&path).unwrap();
        let mut wrong_key_config = fixture.config.clone();
        wrong_key_config.controller_public_key = public_key(&SigningKey::from_bytes(&[8; 32]));
        let wrong_key_path = fixture.write_route(&fixture.route(1, 20_100, 1));
        assert!(load_managed_routes(&wrong_key_config, 16, OffsetDateTime::now_utc()).is_err());

        fs::remove_file(wrong_key_path).unwrap();
        let expired = fixture.route_with(fixture.route_id, 1, 20_100, 1, true);
        fixture.write_route(&expired);
        assert!(fixture.load().unwrap().routes.is_empty());
    }

    #[test]
    fn time_boundary_changes_fingerprint_and_withdraws_without_file_mutation() {
        let fixture = Fixture::new();
        let route = fixture.route(1, 20_100, 1);
        fixture.write_route(&route);
        let active = load_managed_routes(
            &fixture.config,
            16,
            route.header.not_before.as_datetime() + Duration::seconds(1),
        )
        .unwrap();
        let expired =
            load_managed_routes(&fixture.config, 16, route.header.expires_at.as_datetime())
                .unwrap();
        assert_eq!(active.routes.len(), 1);
        assert!(expired.routes.is_empty());
        assert_ne!(active.fingerprint, expired.fingerprint);
    }

    #[test]
    fn rejects_oversize_partial_unknown_extension_and_insecure_mode() {
        let fixture = Fixture::new();
        let path = fixture.directory.path().join("route.json");
        fs::write(
            &path,
            vec![b'x'; usize::try_from(MAX_ROUTE_FILE_BYTES + 1).unwrap()],
        )
        .unwrap();
        set_owner_only(&path, false);
        assert!(fixture.load().is_err());

        fs::write(&path, b"{").unwrap();
        set_owner_only(&path, false);
        assert!(fixture.load().is_err());

        fs::remove_file(&path).unwrap();
        let unknown = fixture.directory.path().join("route.tmp");
        fs::write(&unknown, b"{}").unwrap();
        set_owner_only(&unknown, false);
        assert!(fixture.load().is_err());

        fs::remove_file(&unknown).unwrap();
        let valid = fixture.route(1, 20_100, 1);
        let path = fixture.write_route(&valid);
        set_world_readable(&path);
        assert!(fixture.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_route_file() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let target = fixture.directory.path().join("target");
        fs::write(
            &target,
            serde_json::to_vec(&fixture.route(1, 20_100, 1)).unwrap(),
        )
        .unwrap();
        set_owner_only(&target, false);
        let route = fixture.route(1, 20_100, 1);
        symlink(
            &target,
            fixture
                .directory
                .path()
                .join(format!("{}.relay-route.json", route.header.grant_id)),
        )
        .unwrap();
        assert!(fixture.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_wrong_file_owner() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = Fixture::new();
        let path = fixture.write_route(&fixture.route(1, 20_100, 1));
        let metadata = fs::metadata(path).unwrap();
        assert!(validate_file_metadata(&metadata, metadata.uid().wrapping_add(1)).is_err());
    }

    #[test]
    fn rejects_duplicate_route_and_public_port_and_server_ceiling() {
        let fixture = Fixture::new();
        let first = fixture.route(1, 20_100, 1);
        let duplicate_generation = fixture.route(1, 20_101, 2);
        let first_path = fixture.write_route(&first);
        let second_path = fixture.write_route(&duplicate_generation);
        assert!(fixture.load().is_err());

        fs::remove_file(&second_path).unwrap();
        let duplicate_port = fixture.route_with(RelayRouteId::new(), 1, 20_100, 2, false);
        let duplicate_port_path = fixture.write_route(&duplicate_port);
        assert!(fixture.load().is_err());

        fs::remove_file(duplicate_port_path).unwrap();
        fs::remove_file(first_path).unwrap();
        let mut over_ceiling = fixture.route(1, 20_100, 1);
        over_ceiling.header.limits.max_concurrent_streams = 33;
        sign(&mut over_ceiling, &fixture.signing_key);
        fixture.write_route(&over_ceiling);
        assert!(fixture.load().is_err());
    }

    #[test]
    fn rejects_static_managed_public_port_conflicts() {
        let static_route = RouteConfig {
            route_id: "route_static_0123456789".to_owned(),
            public_listen: "0.0.0.0:20100".parse().unwrap(),
            node_token_sha256: "11".repeat(32),
            node_cert_sha256: "22".repeat(32),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            enabled: true,
            max_concurrent_streams: 1,
            max_bytes_per_second: 1_024,
            max_bytes_per_connection: 1_024,
            monthly_byte_limit: None,
        };
        let managed_route = RouteConfig {
            public_listen: "127.0.0.2:20100".parse().unwrap(),
            ..static_route.clone()
        };

        assert!(
            validate_static_managed_listener_conflicts(&[static_route], &[managed_route]).is_err()
        );
    }

    fn public_key(signing_key: &SigningKey) -> Ed25519PublicKey {
        URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().to_bytes())
            .parse()
            .unwrap()
    }

    fn sign(route: &mut SignedRelayRoute, signing_key: &SigningKey) {
        let signature = signing_key.sign(&relay_route_transcript(route).unwrap());
        route.signature = URL_SAFE_NO_PAD
            .encode(signature.to_bytes())
            .parse::<Ed25519Signature>()
            .unwrap();
    }

    #[cfg(unix)]
    fn set_owner_only(path: &Path, directory: bool) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }

    #[cfg(not(unix))]
    fn set_owner_only(_path: &Path, _directory: bool) {}

    #[cfg(unix)]
    fn set_world_readable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_world_readable(_path: &Path) {}
}
