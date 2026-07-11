//! Version constants shared by every protocol participant.

/// Current HTTP API version.
pub const API_VERSION: u16 = 1;
/// Base path for the current HTTP API.
pub const API_BASE_PATH: &str = "/v1";
/// Current node enrollment schema version.
pub const NODE_ENROLLMENT_SCHEMA_VERSION: u16 = 1;
/// Current heartbeat schema version.
pub const NODE_HEARTBEAT_SCHEMA_VERSION: u16 = 1;
/// Current desired-state document schema version.
pub const DESIRED_STATE_SCHEMA_VERSION: u16 = 1;
/// Current member session schema version.
pub const MEMBER_SESSION_SCHEMA_VERSION: u16 = 1;
/// Current signed profile-bundle schema version.
pub const PROFILE_BUNDLE_SCHEMA_VERSION: u16 = 1;
/// Current decrypted profile payload format version.
pub const PROFILE_PAYLOAD_FORMAT_VERSION: u16 = 1;
/// Current telemetry batch schema version.
pub const TELEMETRY_SCHEMA_VERSION: u16 = 1;
