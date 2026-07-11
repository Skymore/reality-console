//! Verified Xray configuration and process boundary for Node Host.
//!
//! This crate deliberately has a narrow scope:
//!
//! - build deterministic VLESS + REALITY server configuration;
//! - verify explicitly selected Xray executable and configuration files by
//!   SHA-256; and
//! - run bounded probes or start a tightly constrained managed child without a
//!   shell.
//!
//! It does not download Xray, discover it through `PATH`, generate keys, implement
//! a supervisor, activate configuration, or implement rollback.

mod binary;
mod config;
mod config_file;
mod process;

pub use binary::{BinaryValidationError, Sha256Digest, VerifiedXrayBinary, XrayBinarySpec};
pub use config::{
    ConfigBuildError, RealityPrivateKey, RealityTarget, RenderedXrayConfig, ServerName, ShortId,
    UserEmail, VlessRealityConfigBuilder, VlessUser,
};
pub use config_file::{ConfigValidationError, VerifiedXrayConfig, XrayConfigSpec};
pub use process::{
    probe_version, start_managed, test_config, ConfigTestReport, ExecutionLimits, ManagedXrayChild,
    RuntimeError, VersionProbe,
};
