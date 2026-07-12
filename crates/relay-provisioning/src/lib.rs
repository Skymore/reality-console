//! Relay client material issuance and crash-safe managed-route publication.

use control_protocol::crypto::Sha256Digest;
use control_protocol::id::{NodeId, RelayGrantId, Timestamp};
use control_protocol::relay::{
    relay_token_digest, RelayAssignmentMaterial, SignedRelayRoute, RELAY_SCHEMA_VERSION,
};
use control_protocol::secret::Secret;
use rand_core::{OsRng, RngCore as _};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const MAX_CA_PEM_BYTES: u64 = 65_536;
const MAX_ROUTE_DOCUMENT_BYTES: usize = 65_536;
const ROUTE_FILE_SUFFIX: &str = ".relay-route.json";

/// In-memory issued route material plus non-secret digests for the Relay route document.
#[derive(Debug)]
pub struct IssuedRelayMaterial {
    /// Node-encrypted assignment plaintext. Callers must encrypt and drop it promptly.
    pub assignment: RelayAssignmentMaterial,
    /// Digest placed in the non-secret Relay route document.
    pub route_token_sha256: Sha256Digest,
    /// Digest of the exact client leaf certificate DER.
    pub client_certificate_sha256: Sha256Digest,
}

/// Owner of one configured relay client certificate authority.
pub struct RelayCertificateAuthority {
    certificate_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl RelayCertificateAuthority {
    /// Loads an existing owner-only CA certificate and private key without following symlinks.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths/permissions, oversized PEM, or invalid CA material.
    pub fn load(
        certificate_path: &Path,
        private_key_path: &Path,
    ) -> Result<Self, ProvisioningError> {
        let certificate_pem = read_private_text(certificate_path, MAX_CA_PEM_BYTES)?;
        let private_key_pem = read_private_text(private_key_path, MAX_CA_PEM_BYTES)?;
        let key_pair = KeyPair::from_pem(&private_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&certificate_pem, key_pair)?;
        Ok(Self {
            certificate_pem,
            issuer,
        })
    }

    /// Issues a fresh route token and short-lived client certificate for one exact grant.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested validity is invalid or certificate generation fails.
    pub fn issue(
        &self,
        node_id: NodeId,
        grant_id: RelayGrantId,
        not_before: Timestamp,
        expires_at: Timestamp,
    ) -> Result<IssuedRelayMaterial, ProvisioningError> {
        if expires_at <= not_before {
            return Err(ProvisioningError::InvalidValidity);
        }
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(
            DnType::CommonName,
            format!("relay-node:{node_id}:grant:{grant_id}"),
        );
        params.not_before = not_before.as_datetime();
        params.not_after = expires_at.as_datetime();
        params.use_authority_key_identifier_extension = true;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
        let leaf_key = KeyPair::generate()?;
        let certificate = params.signed_by(&leaf_key, &self.issuer)?;
        let certificate_der = certificate.der();
        let certificate_sha256 =
            Sha256Digest::from_bytes(Sha256::digest(certificate_der.as_ref()).into());
        let mut route_token = [0_u8; 32];
        OsRng.fill_bytes(&mut route_token);
        let route_token_sha256 = relay_token_digest(&route_token);
        let assignment = RelayAssignmentMaterial {
            route_token: Secret::new(base64url(&route_token)),
            client_certificate_pem: Secret::new(certificate.pem()),
            client_private_key_pem: Secret::new(leaf_key.serialize_pem()),
            relay_ca_certificate_pem: self.certificate_pem.clone(),
        };
        assignment.validate()?;
        Ok(IssuedRelayMaterial {
            assignment,
            route_token_sha256,
            client_certificate_sha256: certificate_sha256,
        })
    }
}

/// Crash-safe owner-only directory containing signed managed route documents.
#[derive(Debug, Clone)]
pub struct ManagedRouteStore {
    directory: PathBuf,
}

impl ManagedRouteStore {
    /// Opens an existing safe route directory. It is never created implicitly.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is a symlink, not a directory, or has unsafe permissions.
    pub fn open(directory: &Path) -> Result<Self, ProvisioningError> {
        validate_private_directory(directory)?;
        Ok(Self {
            directory: directory.to_path_buf(),
        })
    }

    /// Atomically publishes an exact signed route document.
    ///
    /// An identical existing document is idempotent. A different document for the same grant ID is
    /// a conflict; rotation must use a new grant/generation and revoke the predecessor explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid route metadata, unsafe existing files, conflict, or I/O failure.
    pub fn publish(&self, route: &SignedRelayRoute) -> Result<Sha256Digest, ProvisioningError> {
        route.validate()?;
        if route.header.schema_version != RELAY_SCHEMA_VERSION {
            return Err(ProvisioningError::InvalidRoute);
        }
        let bytes = serde_json::to_vec(route)?;
        if bytes.len() > MAX_ROUTE_DOCUMENT_BYTES {
            return Err(ProvisioningError::RouteTooLarge);
        }
        let digest = Sha256Digest::from_bytes(Sha256::digest(&bytes).into());
        let destination = self.route_path(route.header.grant_id);
        if destination.exists() {
            let existing = read_route_bytes(&destination)?;
            if existing == bytes {
                return Ok(digest);
            }
            return Err(ProvisioningError::RouteConflict);
        }
        let temporary = self.temporary_path(route.header.grant_id);
        let result = (|| -> Result<(), ProvisioningError> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            set_owner_only_create(&mut options);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &destination)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        Ok(digest)
    }

    /// Removes one exact grant document and syncs the containing directory.
    ///
    /// Missing routes are idempotent. Existing symlinks or non-regular files fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe entry or failed durable removal.
    pub fn revoke(&self, grant_id: RelayGrantId) -> Result<bool, ProvisioningError> {
        let path = self.route_path(grant_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProvisioningError::UnsafePath);
        }
        fs::remove_file(path)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(true)
    }

    /// Observes the exact persisted document digest, if the safe route exists.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe or oversized route entries.
    pub fn observed_digest(
        &self,
        grant_id: RelayGrantId,
    ) -> Result<Option<Sha256Digest>, ProvisioningError> {
        let path = self.route_path(grant_id);
        match read_route_bytes(&path) {
            Ok(bytes) => Ok(Some(Sha256Digest::from_bytes(Sha256::digest(bytes).into()))),
            Err(ProvisioningError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn route_path(&self, grant_id: RelayGrantId) -> PathBuf {
        self.directory
            .join(format!("{grant_id}{ROUTE_FILE_SUFFIX}"))
    }

    fn temporary_path(&self, grant_id: RelayGrantId) -> PathBuf {
        let mut random = [0_u8; 8];
        OsRng.fill_bytes(&mut random);
        self.directory
            .join(format!(".{grant_id}-{}.tmp", u64::from_ne_bytes(random)))
    }
}

fn read_route_bytes(path: &Path) -> Result<Vec<u8>, ProvisioningError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProvisioningError::UnsafePath);
    }
    if metadata.len() > MAX_ROUTE_DOCUMENT_BYTES as u64 {
        return Err(ProvisioningError::RouteTooLarge);
    }
    let mut file = File::open(path)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ProvisioningError::RouteTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut file)
        .take(MAX_ROUTE_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_ROUTE_DOCUMENT_BYTES {
        return Err(ProvisioningError::RouteTooLarge);
    }
    Ok(bytes)
}

fn read_private_text(path: &Path, max_bytes: u64) -> Result<String, ProvisioningError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(ProvisioningError::UnsafePath);
    }
    ensure_owner_only(path, &metadata)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ProvisioningError::UnsafePath)?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ProvisioningError::UnsafePath);
    }
    String::from_utf8(bytes).map_err(|_| ProvisioningError::InvalidPem)
}

fn validate_private_directory(path: &Path) -> Result<(), ProvisioningError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProvisioningError::UnsafePath);
    }
    ensure_owner_only(path, &metadata)
}

#[cfg(unix)]
fn ensure_owner_only(_path: &Path, metadata: &fs::Metadata) -> Result<(), ProvisioningError> {
    use std::os::unix::fs::PermissionsExt as _;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProvisioningError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path, _metadata: &fs::Metadata) -> Result<(), ProvisioningError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_owner_only_create(_options: &mut OpenOptions) {}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Relay provisioning boundary failure.
#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
    /// Filesystem I/O failed.
    #[error("relay provisioning I/O failed")]
    Io(#[from] std::io::Error),
    /// CA or leaf certificate generation failed.
    #[error("relay certificate operation failed")]
    Certificate(#[from] rcgen::Error),
    /// Protocol validation failed.
    #[error("relay protocol validation failed")]
    Validation(#[from] control_protocol::ProtocolValidationError),
    /// Route serialization failed.
    #[error("relay route serialization failed")]
    Serialization(#[from] serde_json::Error),
    /// A path is a symlink, wrong type, or otherwise unsafe.
    #[error("relay provisioning path is unsafe")]
    UnsafePath,
    /// A secret or route directory grants group/world access.
    #[error("relay provisioning path permissions are unsafe")]
    UnsafePermissions,
    /// A requested certificate lifetime is empty or reversed.
    #[error("relay certificate validity is invalid")]
    InvalidValidity,
    /// CA PEM is not valid UTF-8 or cannot be parsed.
    #[error("relay certificate authority PEM is invalid")]
    InvalidPem,
    /// Route document exceeds the strict size limit.
    #[error("relay route document exceeds its size limit")]
    RouteTooLarge,
    /// Route metadata is inconsistent with the supported schema.
    #[error("relay route document is invalid")]
    InvalidRoute,
    /// An existing grant path contains different bytes.
    #[error("relay route document conflicts with an existing grant")]
    RouteConflict,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use control_protocol::crypto::{Ed25519Signature, Sha256Digest};
    use control_protocol::id::{
        EndpointId, NetworkId, RelayGeneration, RelayId, RelayRouteId, SigningKeyId,
    };
    use control_protocol::relay::{RelayAssignmentHeader, RelayLimits};
    use ed25519_dalek::{Signer as _, SigningKey};
    use rcgen::{BasicConstraints, IsCa};
    use tempfile::TempDir;
    use time::{Duration, OffsetDateTime};

    #[cfg(unix)]
    fn owner_only(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(not(unix))]
    fn owner_only(_path: &Path) {}

    fn authority(directory: &Path) -> RelayCertificateAuthority {
        let mut params = CertificateParams::new(vec!["Relay Test CA".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert_path = directory.join("ca.pem");
        let key_path = directory.join("ca-key.pem");
        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        RelayCertificateAuthority::load(&cert_path, &key_path).unwrap()
    }

    fn route() -> SignedRelayRoute {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        SignedRelayRoute {
            header: RelayAssignmentHeader {
                schema_version: RELAY_SCHEMA_VERSION,
                network_id: NetworkId::new(),
                node_id: NodeId::new(),
                relay_id: RelayId::new(),
                route_id: RelayRouteId::new(),
                grant_id: RelayGrantId::new(),
                generation: RelayGeneration::new(1).unwrap(),
                endpoint_id: EndpointId::new(),
                public_host: "relay.example.test".into(),
                public_port: 20_001,
                tunnel_host: "relay.example.test".into(),
                tunnel_port: 9443,
                tls_server_name: "relay.example.test".into(),
                issued_at: Timestamp::from_datetime(now),
                not_before: Timestamp::from_datetime(now),
                expires_at: Timestamp::from_datetime(now + Duration::hours(12)),
                limits: RelayLimits {
                    max_concurrent_streams: 16,
                    max_bytes_per_second: 2_500_000,
                    max_bytes_per_connection: 10_000_000,
                    monthly_byte_limit: 100_000_000,
                },
            },
            route_token_sha256: Sha256Digest::from_bytes([1_u8; 32]),
            client_certificate_sha256: Sha256Digest::from_bytes([2_u8; 32]),
            signing_key_id: SigningKeyId::new(),
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]).parse().unwrap(),
        }
    }

    #[test]
    fn issues_unique_bounded_material_without_debug_disclosure() {
        let temporary = TempDir::new().unwrap();
        owner_only(temporary.path());
        let authority = authority(temporary.path());
        let now = OffsetDateTime::now_utc();
        let first = authority
            .issue(
                NodeId::new(),
                RelayGrantId::new(),
                Timestamp::from_datetime(now),
                Timestamp::from_datetime(now + Duration::hours(1)),
            )
            .unwrap();
        let second = authority
            .issue(
                NodeId::new(),
                RelayGrantId::new(),
                Timestamp::from_datetime(now),
                Timestamp::from_datetime(now + Duration::hours(1)),
            )
            .unwrap();
        assert_ne!(
            first.assignment.route_token.expose_secret(),
            second.assignment.route_token.expose_secret()
        );
        let debug = format!("{first:?}");
        assert!(!debug.contains(first.assignment.route_token.expose_secret()));
        assert!(first.assignment.validate().is_ok());
    }

    #[test]
    fn route_publish_is_atomic_idempotent_and_conflict_safe() {
        let temporary = TempDir::new().unwrap();
        owner_only(temporary.path());
        let store = ManagedRouteStore::open(temporary.path()).unwrap();
        let route = route();
        let digest = store.publish(&route).unwrap();
        assert_eq!(store.publish(&route).unwrap(), digest);
        assert_eq!(
            store.observed_digest(route.header.grant_id).unwrap(),
            Some(digest)
        );

        let mut changed = route.clone();
        changed.signature = URL_SAFE_NO_PAD.encode([3_u8; 64]).parse().unwrap();
        assert!(matches!(
            store.publish(&changed),
            Err(ProvisioningError::RouteConflict)
        ));
        assert!(store.revoke(route.header.grant_id).unwrap());
        assert!(!store.revoke(route.header.grant_id).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_directory_and_symlink_route_fail_closed() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            ManagedRouteStore::open(temporary.path()),
            Err(ProvisioningError::UnsafePermissions)
        ));
        owner_only(temporary.path());
        let store = ManagedRouteStore::open(temporary.path()).unwrap();
        let route = route();
        let target = temporary.path().join("target");
        fs::write(&target, "target").unwrap();
        symlink(
            &target,
            temporary
                .path()
                .join(format!("{}{}", route.header.grant_id, ROUTE_FILE_SUFFIX)),
        )
        .unwrap();
        assert!(matches!(
            store.publish(&route),
            Err(ProvisioningError::UnsafePath)
        ));
    }

    #[test]
    fn caller_can_sign_exact_route_after_issuance() {
        let signing = SigningKey::from_bytes(&[8_u8; 32]);
        let mut route = route();
        let transcript = control_protocol::relay::relay_route_transcript(&route).unwrap();
        route.signature = URL_SAFE_NO_PAD
            .encode(signing.sign(&transcript).to_bytes())
            .parse::<Ed25519Signature>()
            .unwrap();
        assert_ne!(route.signature.as_str(), URL_SAFE_NO_PAD.encode([0_u8; 64]));
    }
}
