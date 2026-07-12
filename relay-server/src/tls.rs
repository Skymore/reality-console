use std::{fs::File, io::BufReader, path::Path, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use sha2::{Digest, Sha256};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::ServerConfig as RelayServerConfig,
    error::{RelayError, Result},
};

pub fn build_acceptor(config: &RelayServerConfig) -> Result<TlsAcceptor> {
    ensure_crypto_provider()?;
    let certificates = load_certificates(&config.tls_cert_path)?;
    let private_key = load_private_key(&config.tls_key_path)?;
    let mut client_roots = RootCertStore::empty();
    for certificate in load_certificates(&config.client_ca_path)? {
        client_roots
            .add(certificate)
            .map_err(|error| RelayError::Tls(format!("invalid client CA: {error}")))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|error| RelayError::Tls(format!("cannot build client verifier: {error}")))?;
    let mut server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .map_err(|error| RelayError::Tls(format!("invalid server identity: {error}")))?;
    server.alpn_protocols = vec![b"pn-relay-v1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server)))
}

pub(crate) fn ensure_crypto_provider() -> Result<()> {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return Ok(());
    }
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| RelayError::Tls("cannot install the process TLS crypto provider".to_owned()))
}

pub fn certificate_sha256(certificate: &CertificateDer<'_>) -> [u8; 32] {
    Sha256::digest(certificate.as_ref()).into()
}

pub(crate) fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|error| RelayError::Tls(format!("cannot open {}: {error}", path.display())))?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            RelayError::Tls(format!(
                "cannot parse certificates in {}: {error}",
                path.display()
            ))
        })?;
    if certificates.is_empty() {
        return Err(RelayError::Tls(format!(
            "{} contains no certificates",
            path.display()
        )));
    }
    Ok(certificates)
}

pub(crate) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    enforce_private_file_permissions(path)?;
    let file = File::open(path)
        .map_err(|error| RelayError::Tls(format!("cannot open {}: {error}", path.display())))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|error| {
            RelayError::Tls(format!(
                "cannot parse private key in {}: {error}",
                path.display()
            ))
        })?
        .ok_or_else(|| RelayError::Tls(format!("{} contains no private key", path.display())))
}

#[cfg(unix)]
pub(crate) fn enforce_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)
        .map_err(|error| RelayError::Tls(format!("cannot inspect {}: {error}", path.display())))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(RelayError::Tls(format!(
            "{} must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn enforce_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
