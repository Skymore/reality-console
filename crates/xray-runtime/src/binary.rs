use std::{
    fmt,
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::{fs::OpenOptionsExt, fs::PermissionsExt},
};

use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;

/// A caller-supplied SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Parses exactly 64 hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`BinaryValidationError::InvalidDigest`] for malformed input.
    pub fn from_hex(value: &str) -> Result<Self, BinaryValidationError> {
        if value.len() != 64 {
            return Err(BinaryValidationError::InvalidDigest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex(pair[0]).ok_or(BinaryValidationError::InvalidDigest)?;
            let low = decode_hex(pair[1]).ok_or(BinaryValidationError::InvalidDigest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub(crate) fn matches(self, actual: &[u8]) -> bool {
        self.0.as_slice() == actual
    }
}

impl FromStr for Sha256Digest {
    type Err = BinaryValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(")?;
        fmt_hex(&self.0, formatter)?;
        formatter.write_str(")")
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_hex(&self.0, formatter)
    }
}

/// Explicit path and trusted digest for an Xray executable.
#[derive(Clone, Debug)]
pub struct XrayBinarySpec {
    path: PathBuf,
    expected_sha256: Sha256Digest,
}

impl XrayBinarySpec {
    /// Creates a binary specification without consulting `PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`BinaryValidationError::PathMustBeAbsolute`] unless `path` is
    /// absolute.
    pub fn new(
        path: impl Into<PathBuf>,
        expected_sha256: Sha256Digest,
    ) -> Result<Self, BinaryValidationError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(BinaryValidationError::PathMustBeAbsolute);
        }
        Ok(Self {
            path,
            expected_sha256,
        })
    }

    /// Validates file type, Unix executable bits, and SHA-256.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when the executable cannot be trusted.
    pub fn verify(&self) -> Result<VerifiedXrayBinary, BinaryValidationError> {
        verify_path(&self.path, self.expected_sha256)?;
        Ok(VerifiedXrayBinary { spec: self.clone() })
    }
}

/// An Xray executable that passed explicit local validation.
///
/// Runtime operations revalidate the file before each spawn to catch ordinary
/// replacement or mutation after this value was created.
#[derive(Clone, Debug)]
pub struct VerifiedXrayBinary {
    spec: XrayBinarySpec,
}

impl VerifiedXrayBinary {
    /// Returns the explicit absolute executable path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.spec.path
    }

    pub(crate) fn revalidate(&self) -> Result<(), BinaryValidationError> {
        verify_path(&self.spec.path, self.spec.expected_sha256)
    }
}

/// Stable errors produced while validating an explicit Xray executable.
#[derive(Debug, Error)]
pub enum BinaryValidationError {
    /// The expected digest was not exactly 32 hexadecimal bytes.
    #[error("expected Xray SHA-256 digest is invalid")]
    InvalidDigest,
    /// The executable path was relative.
    #[error("Xray binary path must be absolute")]
    PathMustBeAbsolute,
    /// The path could not be inspected.
    #[error("Xray binary could not be inspected")]
    InspectFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// Symbolic links are intentionally rejected.
    #[error("Xray binary must not be a symbolic link")]
    SymlinkNotAllowed,
    /// The opened object was not a regular file.
    #[error("Xray binary must be a regular file")]
    NotRegularFile,
    /// No Unix executable bit was present.
    #[error("Xray binary is not executable")]
    NotExecutable,
    /// The executable was writable by group or other users.
    #[error("Xray binary permissions are unsafe")]
    UnsafePermissions,
    /// The executable was empty or exceeded the bounded hashing size.
    #[error("Xray binary size is invalid")]
    InvalidFileSize,
    /// The file could not be opened without following links.
    #[error("Xray binary could not be opened safely")]
    OpenFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The file could not be hashed.
    #[error("Xray binary could not be hashed")]
    HashFailed {
        /// Underlying filesystem failure, excluded from the top-level message.
        #[source]
        source: io::Error,
    },
    /// The file digest did not match the caller's trusted digest.
    #[error("Xray binary SHA-256 checksum mismatch")]
    ChecksumMismatch,
    /// Executable-bit validation is unavailable on this platform.
    #[error("Xray binary validation requires a Unix platform")]
    UnsupportedPlatform,
}

fn verify_path(path: &Path, expected: Sha256Digest) -> Result<(), BinaryValidationError> {
    let link_metadata = fs::symlink_metadata(path)
        .map_err(|source| BinaryValidationError::InspectFailed { source })?;
    if link_metadata.file_type().is_symlink() {
        return Err(BinaryValidationError::SymlinkNotAllowed);
    }

    let file = open_without_following_links(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| BinaryValidationError::InspectFailed { source })?;
    if !metadata.is_file() {
        return Err(BinaryValidationError::NotRegularFile);
    }
    if metadata.len() == 0 || metadata.len() > MAX_BINARY_BYTES {
        return Err(BinaryValidationError::InvalidFileSize);
    }
    validate_executable(&metadata)?;

    let actual = hash_file(file)?;
    if !expected.matches(&actual) {
        return Err(BinaryValidationError::ChecksumMismatch);
    }
    Ok(())
}

#[cfg(unix)]
fn open_without_following_links(path: &Path) -> Result<File, BinaryValidationError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| BinaryValidationError::OpenFailed { source })
}

#[cfg(not(unix))]
fn open_without_following_links(_path: &Path) -> Result<File, BinaryValidationError> {
    Err(BinaryValidationError::UnsupportedPlatform)
}

#[cfg(unix)]
fn validate_executable(metadata: &fs::Metadata) -> Result<(), BinaryValidationError> {
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(BinaryValidationError::NotExecutable);
    }
    if mode & 0o022 != 0 {
        return Err(BinaryValidationError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable(_metadata: &fs::Metadata) -> Result<(), BinaryValidationError> {
    Err(BinaryValidationError::UnsupportedPlatform)
}

fn hash_file(file: File) -> Result<[u8; 32], BinaryValidationError> {
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| BinaryValidationError::HashFailed { source })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn fmt_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
