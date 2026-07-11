use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;

const MIN_BOOTSTRAP_TOKEN_BYTES: usize = 32;
const MAX_BOOTSTRAP_TOKEN_BYTES: usize = 4096;

/// Stores only a fixed-size verifier, never the raw bootstrap token.
#[derive(Clone)]
pub struct BootstrapTokenVerifier([u8; 32]);

impl BootstrapTokenVerifier {
    /// Builds a fixed-size verifier and discards the caller-owned raw token.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapTokenError::InvalidLength`] when the token is too
    /// short for bootstrap use or exceeds the bounded input size.
    pub fn new(token: &str) -> Result<Self, BootstrapTokenError> {
        let length = token.len();
        if !(MIN_BOOTSTRAP_TOKEN_BYTES..=MAX_BOOTSTRAP_TOKEN_BYTES).contains(&length) {
            return Err(BootstrapTokenError::InvalidLength);
        }

        Ok(Self(Sha256::digest(token.as_bytes()).into()))
    }

    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let candidate_digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(self.0.ct_eq(&candidate_digest))
    }
}

impl fmt::Debug for BootstrapTokenVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapTokenVerifier([REDACTED])")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BootstrapTokenError {
    #[error("bootstrap token must contain between 32 and 4096 bytes")]
    InvalidLength,
}

#[cfg(test)]
mod tests {
    use super::{BootstrapTokenError, BootstrapTokenVerifier};

    const TOKEN: &str = "a-secure-bootstrap-token-with-32-bytes";

    #[test]
    fn verifies_without_retaining_a_debuggable_secret() {
        let verifier = BootstrapTokenVerifier::new(TOKEN).unwrap();

        assert!(verifier.verify(TOKEN));
        assert!(!verifier.verify("a-different-bootstrap-token-32-bytes"));
        assert_eq!(
            format!("{verifier:?}"),
            "BootstrapTokenVerifier([REDACTED])"
        );
        assert!(!format!("{verifier:?}").contains(TOKEN));
    }

    #[test]
    fn rejects_short_tokens() {
        assert_eq!(
            BootstrapTokenVerifier::new("too-short").unwrap_err(),
            BootstrapTokenError::InvalidLength
        );
    }
}
