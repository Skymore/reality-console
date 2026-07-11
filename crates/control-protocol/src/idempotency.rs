//! Bounded HTTP idempotency-key contract shared by mutating clients.

use crate::{ProtocolValidationError, ValidationCode};
use std::fmt;
use std::str::FromStr;

/// Standard header used to make retryable mutations durable and replay-safe.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

/// Opaque, bounded idempotency key supplied by the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Returns the caller-provided key. It must be hashed before persistence.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([REDACTED])")
    }
}

impl FromStr for IdempotencyKey {
    type Err = ProtocolValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(ProtocolValidationError::new(
                ValidationCode::MissingField,
                "Idempotency-Key",
                "idempotency key is required",
            ));
        }
        if value.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || !value.as_bytes().iter().all(u8::is_ascii_graphic)
        {
            return Err(ProtocolValidationError::new(
                ValidationCode::InvalidFormat,
                "Idempotency-Key",
                "idempotency key must contain 1 to 128 visible ASCII bytes",
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::IdempotencyKey;

    #[test]
    fn accepts_bounded_visible_ascii_without_exposing_debug_value() {
        let key: IdempotencyKey = "account-create-42".parse().unwrap();

        assert_eq!(key.as_str(), "account-create-42");
        assert_eq!(format!("{key:?}"), "IdempotencyKey([REDACTED])");
    }

    #[test]
    fn rejects_empty_whitespace_unicode_and_oversized_values() {
        for value in ["", "contains space", "snowman-☃", &"x".repeat(129)] {
            assert!(value.parse::<IdempotencyKey>().is_err());
        }
    }
}
