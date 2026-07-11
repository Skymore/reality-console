//! Verified Xray configuration and process boundary for Node Host.
//!
//! This crate deliberately has a narrow scope:
//!
//! - build deterministic VLESS + REALITY server configuration;
//! - verify an explicitly selected Xray executable by SHA-256; and
//! - run bounded version and configuration-test subprocesses without a shell.
//!
//! It does not download Xray, discover it through `PATH`, generate keys, supervise
//! a long-running process, activate configuration, or implement rollback.

mod binary;
mod config;
mod process;

pub use binary::{BinaryValidationError, Sha256Digest, VerifiedXrayBinary, XrayBinarySpec};
pub use config::{
    ConfigBuildError, RealityPrivateKey, RealityTarget, RenderedXrayConfig, ServerName, ShortId,
    UserEmail, VlessRealityConfigBuilder, VlessUser,
};
pub use process::{
    probe_version, test_config, ConfigTestReport, ExecutionLimits, RuntimeError, VersionProbe,
};
