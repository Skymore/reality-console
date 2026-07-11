//! Shared, transport-independent protocol and domain types.
//!
//! This crate intentionally contains no HTTP, persistence, process, UI, or
//! filesystem integration. Callers remain responsible for authenticating and
//! cryptographically verifying signed values before trusting them.

pub mod account;
pub mod crypto;
pub mod desired;
pub mod enrollment;
pub mod error;
pub mod id;
pub mod node;
pub mod request_auth;
pub mod secret;
pub mod telemetry;
pub mod validation;
pub mod version;

pub use validation::{ProtocolValidationError, ValidationCode};
