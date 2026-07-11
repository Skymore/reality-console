use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use control_protocol::crypto::{Ed25519PublicKey, Ed25519Signature, Sha256Digest};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;
use tempfile::NamedTempFile;
use thiserror::Error;

const IDENTITY_MAGIC: &[u8; 8] = b"RCTLKEY\x01";
const IDENTITY_FILE_LENGTH: usize = IDENTITY_MAGIC.len() + 32;

/// Controller signing identity backed by an owner-only sidecar seed file.
#[derive(Clone)]
pub struct ControllerIdentity {
    signing_key: Arc<SigningKey>,
    public_key: Ed25519PublicKey,
    fingerprint: Sha256Digest,
    path: PathBuf,
}

impl ControllerIdentity {
    /// Loads the controller identity or atomically creates it beside the database.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] for unsafe paths, invalid persisted material, or I/O.
    pub fn load_or_create(database_path: &Path) -> Result<Self, IdentityError> {
        let path = identity_path(database_path);
        if path.exists() {
            return Self::load(&path);
        }

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut material = Vec::with_capacity(IDENTITY_FILE_LENGTH);
        material.extend_from_slice(IDENTITY_MAGIC);
        material.extend_from_slice(&signing_key.to_bytes());

        let mut temporary = NamedTempFile::new_in(parent)?;
        set_owner_only(temporary.path())?;
        temporary.write_all(&material)?;
        temporary.as_file().sync_all()?;

        match temporary.persist_noclobber(&path) {
            Ok(file) => {
                file.sync_all()?;
                sync_parent(parent)?;
                Self::from_signing_key(signing_key, path)
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::load(&path)
            }
            Err(error) => Err(IdentityError::Io(error.error)),
        }
    }

    fn load(path: &Path) -> Result<Self, IdentityError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(IdentityError::UnsafeIdentityPath(path.to_path_buf()));
        }
        set_owner_only(path)?;
        let material = fs::read(path)?;
        if material.len() != IDENTITY_FILE_LENGTH
            || &material[..IDENTITY_MAGIC.len()] != IDENTITY_MAGIC
        {
            return Err(IdentityError::InvalidIdentityFile(path.to_path_buf()));
        }
        let seed: [u8; 32] = material[IDENTITY_MAGIC.len()..]
            .try_into()
            .map_err(|_| IdentityError::InvalidIdentityFile(path.to_path_buf()))?;
        Self::from_signing_key(SigningKey::from_bytes(&seed), path.to_path_buf())
    }

    fn from_signing_key(signing_key: SigningKey, path: PathBuf) -> Result<Self, IdentityError> {
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_key = Ed25519PublicKey::from_str(&URL_SAFE_NO_PAD.encode(public_bytes))
            .map_err(|_| IdentityError::Encoding)?;
        let digest = Sha256::digest(public_bytes);
        let fingerprint = Sha256Digest::from_str(&format!("sha256:{digest:x}"))
            .map_err(|_| IdentityError::Encoding)?;
        Ok(Self {
            signing_key: Arc::new(signing_key),
            public_key,
            fingerprint,
            path,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        self.public_key.clone()
    }

    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        self.fingerprint.clone()
    }

    /// Signs a canonical protocol transcript.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Encoding`] if the fixed-size protocol wrapper
    /// unexpectedly rejects a valid Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, IdentityError> {
        let signature = self.signing_key.sign(message);
        URL_SAFE_NO_PAD
            .encode(signature.to_bytes())
            .parse()
            .map_err(|_| IdentityError::Encoding)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for ControllerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerIdentity")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn identity_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push(".controller-ed25519");
    PathBuf::from(value)
}

#[cfg(unix)]
pub(crate) fn set_owner_only(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub(crate) fn set_owner_only(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("controller identity path is not a regular file: {0}")]
    UnsafeIdentityPath(PathBuf),
    #[error("controller identity file is invalid: {0}")]
    InvalidIdentityFile(PathBuf),
    #[error("controller identity could not be encoded")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::{identity_path, ControllerIdentity};
    use tempfile::TempDir;

    #[test]
    fn identity_survives_restart_without_entering_sqlite() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("control.sqlite3");
        let first = ControllerIdentity::load_or_create(&database).unwrap();
        let first_public = first.public_key();
        drop(first);

        let reopened = ControllerIdentity::load_or_create(&database).unwrap();
        assert_eq!(reopened.public_key(), first_public);
        assert_eq!(reopened.path(), identity_path(&database));
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let database = temp.path().join("control.sqlite3");
        let identity = ControllerIdentity::load_or_create(&database).unwrap();
        let mode = std::fs::metadata(identity.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
