use std::{
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::{fs::OpenOptionsExt, fs::PermissionsExt},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::Sha256Digest;

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;

/// Explicit path and trusted digest for an Xray configuration file.
#[derive(Clone, Debug)]
pub struct XrayConfigSpec {
    path: PathBuf,
    expected_sha256: Sha256Digest,
}

impl XrayConfigSpec {
    /// Creates a configuration specification without path discovery.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigValidationError::PathMustBeAbsolute`] unless `path` is
    /// absolute.
    pub fn new(
        path: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
    ) -> Result<Self, ConfigValidationError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(ConfigValidationError::PathMustBeAbsolute);
        }
        Ok(Self {
            path,
            expected_sha256,
        })
    }

    /// Validates file type, owner-only permissions, size, and SHA-256.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when the configuration file cannot be
    /// trusted.
    pub fn verify(&self) -> Result<VerifiedXrayConfig, ConfigValidationError> {
        verify_path(&self.path, self.expected_sha256)?;
        Ok(VerifiedXrayConfig { spec: self.clone() })
    }
}

/// An Xray configuration file that passed explicit local validation.
///
/// Managed process startup revalidates the file before every spawn to catch
/// ordinary replacement or mutation after this value was created.
#[derive(Clone, Debug)]
pub struct VerifiedXrayConfig {
    spec: XrayConfigSpec,
}

impl VerifiedXrayConfig {
    /// Returns the explicit absolute configuration path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.spec.path
    }

    pub(crate) fn revalidate(&self) -> Result<(), ConfigValidationError> {
        verify_path(&self.spec.path, self.spec.expected_sha256)
    }
}

/// Stable errors produced while validating an explicit Xray configuration file.
#[derive(Debug, Error)]
pub enum ConfigValidationError {
    /// The configuration path was relative.
    #[error("Xray configuration path must be absolute")]
    PathMustBeAbsolute,
    /// The path could not be inspected.
    #[error("Xray configuration file could not be inspected")]
    InspectFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// Symbolic links are intentionally rejected.
    #[error("Xray configuration file must not be a symbolic link")]
    SymlinkNotAllowed,
    /// The opened object was not a regular file.
    #[error("Xray configuration must be a regular file")]
    NotRegularFile,
    /// The configuration access mode was not exactly `0600`.
    #[error("Xray configuration file permissions are unsafe")]
    UnsafePermissions,
    /// The configuration was empty or exceeded two MiB.
    #[error("Xray configuration file size is invalid")]
    InvalidFileSize,
    /// The file could not be opened without following links or blocking on a FIFO.
    #[error("Xray configuration file could not be opened safely")]
    OpenFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The file could not be hashed.
    #[error("Xray configuration file could not be hashed")]
    HashFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The file digest did not match the caller's trusted digest.
    #[error("Xray configuration SHA-256 checksum mismatch")]
    ChecksumMismatch,
    /// Owner-only permission validation is unavailable on this platform.
    #[error("Xray configuration validation requires a Unix platform")]
    UnsupportedPlatform,
}

fn verify_path(path: &Path, expected: Sha256Digest) -> Result<(), ConfigValidationError> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|source| ConfigValidationError::InspectFailed { source })?;
    if link_metadata.file_type().is_symlink() {
        return Err(ConfigValidationError::SymlinkNotAllowed);
    }
    if !link_metadata.is_file() {
        return Err(ConfigValidationError::NotRegularFile);
    }

    let file = open_without_following_links(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| ConfigValidationError::InspectFailed { source })?;
    validate_metadata(&metadata)?;

    let actual = hash_file(&file)?;
    let metadata = file
        .metadata()
        .map_err(|source| ConfigValidationError::InspectFailed { source })?;
    validate_metadata(&metadata)?;
    if !expected.matches(&actual) {
        return Err(ConfigValidationError::ChecksumMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn open_without_following_links(path: &Path) -> Result<File, ConfigValidationError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| ConfigValidationError::OpenFailed { source })
}

#[cfg(not(unix))]
fn open_without_following_links(_path: &Path) -> Result<File, ConfigValidationError> {
    Err(ConfigValidationError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_metadata(metadata: &fs::Metadata) -> Result<(), ConfigValidationError> {
    if !metadata.is_file() {
        return Err(ConfigValidationError::NotRegularFile);
    }
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(ConfigValidationError::UnsafePermissions);
    }
    if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigValidationError::InvalidFileSize);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_metadata(_metadata: &fs::Metadata) -> Result<(), ConfigValidationError> {
    Err(ConfigValidationError::UnsupportedPlatform)
}

fn hash_file(file: &File) -> Result<[u8; 32], ConfigValidationError> {
    let mut reader = BufReader::new(file).take(MAX_CONFIG_BYTES + 1);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| ConfigValidationError::HashFailed { source })?;
        if read == 0 {
            break;
        }
        total += u64::try_from(read).expect("buffer length always fits in u64");
        if total > MAX_CONFIG_BYTES {
            return Err(ConfigValidationError::InvalidFileSize);
        }
        hasher.update(&buffer[..read]);
    }
    if total == 0 {
        return Err(ConfigValidationError::InvalidFileSize);
    }
    Ok(hasher.finalize().into())
}
