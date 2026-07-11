//! Secret-bearing values with safe formatting behavior.

use serde::{Deserialize, Serialize};
use std::fmt;

const REDACTED: &str = "[redacted]";

/// A value that serializes for transport but is always redacted from formatting.
///
/// Deliberate access requires [`Secret::expose_secret`]. This wrapper does not
/// encrypt memory and callers must still keep serialized payloads out of logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a secret value.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Deliberately borrows the secret value.
    #[must_use]
    pub const fn expose_secret(&self) -> &T {
        &self.0
    }

    /// Deliberately consumes the wrapper and returns the secret value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn formatting_never_reveals_the_inner_value() {
        let secret = Secret::new("correct horse battery staple".to_string());

        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{secret}"), "[redacted]");
        assert!(!format!("{secret:?}").contains("correct"));
    }

    #[test]
    fn transport_serialization_is_explicitly_supported() {
        let secret = Secret::new("wire-value".to_string());
        let json = serde_json::to_string(&secret).expect("serialize secret wrapper");
        let decoded: Secret<String> = serde_json::from_str(&json).expect("deserialize secret");

        assert_eq!(json, "\"wire-value\"");
        assert_eq!(decoded.expose_secret(), "wire-value");
    }
}
