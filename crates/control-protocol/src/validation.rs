//! Shared validation errors for untrusted protocol values.

use std::error::Error;
use std::fmt;

/// Stable machine-readable validation failure classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationCode {
    /// A required value was absent or empty.
    MissingField,
    /// A numeric or textual value was outside its permitted range.
    OutOfRange,
    /// A value did not have the required syntax.
    InvalidFormat,
    /// A schema version is not supported by this participant.
    UnsupportedSchema,
    /// An artifact was addressed to another identity.
    IdentityMismatch,
    /// A revision or bundle generation would move state backwards.
    StaleState,
    /// State fields contradict one another.
    InconsistentState,
    /// A collection contains duplicate stable identifiers.
    DuplicateIdentity,
    /// An ordered sequence contains a gap or mismatched bounds.
    SequenceGap,
    /// The requested state transition is not monotonic.
    InvalidTransition,
}

/// A safe protocol validation diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolValidationError {
    code: ValidationCode,
    field: &'static str,
    message: &'static str,
}

impl ProtocolValidationError {
    /// Creates a validation error with a non-secret static diagnostic.
    #[must_use]
    pub const fn new(code: ValidationCode, field: &'static str, message: &'static str) -> Self {
        Self {
            code,
            field,
            message,
        }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn code(&self) -> ValidationCode {
        self.code
    }

    /// Returns the protocol field associated with the failure.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the safe diagnostic.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ProtocolValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl Error for ProtocolValidationError {}
