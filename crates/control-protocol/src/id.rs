//! Canonical typed identifiers and monotonic numeric cursors.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

/// Failure to parse a canonical protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a canonical lowercase UUID")
    }
}

impl Error for InvalidId {}

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// Creates a new random version-4 identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let parsed = Uuid::parse_str(value).map_err(|_| InvalidId)?;
                if parsed.hyphenated().to_string() != value {
                    return Err(InvalidId);
                }
                Ok(Self(parsed))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

typed_id!(/// Stable private-network identity.
    NetworkId);
typed_id!(/// Stable administrator identity.
    AdminId);
typed_id!(/// Stable logical member identity.
    UserId);
typed_id!(/// Stable member-device identity.
    DeviceId);
typed_id!(/// Stable node installation identity.
    NodeId);
typed_id!(/// Stable per-user, per-node credential identity.
    CredentialId);
typed_id!(/// Stable immutable configuration-revision identity.
    RevisionId);
typed_id!(/// Stable signed profile-bundle identity.
    BundleId);
typed_id!(/// Stable one-time node-invitation identity.
    NodeInvitationId);
typed_id!(/// Stable device-activation identity.
    DeviceActivationId);
typed_id!(/// Stable device session-family identity.
    SessionId);
typed_id!(/// Stable request correlation identity.
    RequestId);
typed_id!(/// Stable controller instance identity.
    ControllerInstanceId);
typed_id!(/// Stable public signing-key identity.
    SigningKeyId);
typed_id!(/// Stable enrolled node-key identity.
    NodeKeyId);
typed_id!(/// Stable node endpoint identity.
    EndpointId);

/// A positive, monotonically increasing desired-state revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Revision(i64);

impl Revision {
    /// Creates a positive revision.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPositiveNumber`] when `value` is zero or negative.
    pub const fn new(value: i64) -> Result<Self, InvalidPositiveNumber> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(InvalidPositiveNumber)
        }
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A positive, monotonically increasing profile-bundle generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BundleGeneration(i64);

impl BundleGeneration {
    /// Creates a positive generation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPositiveNumber`] when `value` is zero or negative.
    pub const fn new(value: i64) -> Result<Self, InvalidPositiveNumber> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(InvalidPositiveNumber)
        }
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for BundleGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A non-negative telemetry sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SequenceNumber(i64);

impl SequenceNumber {
    /// Creates a non-negative sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNonNegativeNumber`] when `value` is negative.
    pub const fn new(value: i64) -> Result<Self, InvalidNonNegativeNumber> {
        if value >= 0 {
            Ok(Self(value))
        } else {
            Err(InvalidNonNegativeNumber)
        }
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Returns the next sequence, if representable.
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl<'de> Deserialize<'de> for SequenceNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// A non-negative byte count or event count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Count(i64);

impl Count {
    /// Creates a non-negative count.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidNonNegativeNumber`] when `value` is negative.
    pub const fn new(value: i64) -> Result<Self, InvalidNonNegativeNumber> {
        if value >= 0 {
            Ok(Self(value))
        } else {
            Err(InvalidNonNegativeNumber)
        }
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Count {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Error returned for zero or negative protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPositiveNumber;

impl fmt::Display for InvalidPositiveNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a positive signed 64-bit integer")
    }
}

impl Error for InvalidPositiveNumber {}

/// Error returned for negative protocol numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNonNegativeNumber;

impl fmt::Display for InvalidNonNegativeNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a non-negative signed 64-bit integer")
    }
}

impl Error for InvalidNonNegativeNumber {}

/// An RFC 3339 UTC timestamp serialized with a `Z` suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Creates a timestamp after normalizing it to UTC.
    #[must_use]
    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }

    /// Returns the underlying UTC timestamp.
    #[must_use]
    pub const fn as_datetime(self) -> OffsetDateTime {
        self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        formatter.write_str(&value)
    }
}

impl FromStr for Timestamp {
    type Err = InvalidTimestamp;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| InvalidTimestamp)?;
        if parsed.offset() != UtcOffset::UTC || !value.ends_with('Z') {
            return Err(InvalidTimestamp);
        }
        Ok(Self(parsed))
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RFC 3339 UTC timestamp ending in Z")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

/// Failure to parse an RFC 3339 UTC timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTimestamp;

impl fmt::Display for InvalidTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected an RFC 3339 UTC timestamp ending in Z")
    }
}

impl Error for InvalidTimestamp {}

#[cfg(test)]
mod tests {
    use super::{NodeId, Revision, Timestamp};

    #[test]
    fn typed_ids_require_canonical_lowercase_uuid_strings() {
        let canonical = "2f55c837-7be6-4752-b58a-a7f51401bd89";
        let id: NodeId = serde_json::from_str(&format!("\"{canonical}\""))
            .expect("canonical identifier should parse");

        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{canonical}\"")
        );
        assert!("2F55C837-7BE6-4752-B58A-A7F51401BD89"
            .parse::<NodeId>()
            .is_err());
        assert!("2f55c8377be64752b58aa7f51401bd89"
            .parse::<NodeId>()
            .is_err());
    }

    #[test]
    fn revisions_reject_non_positive_values_during_deserialization() {
        assert!(serde_json::from_str::<Revision>("0").is_err());
        assert!(serde_json::from_str::<Revision>("-1").is_err());
    }

    #[test]
    fn timestamps_require_utc_wire_values() {
        let timestamp: Timestamp = serde_json::from_str("\"2026-07-11T20:00:00Z\"").unwrap();

        assert_eq!(timestamp.to_string(), "2026-07-11T20:00:00Z");
        assert!("2026-07-11T13:00:00-07:00".parse::<Timestamp>().is_err());
    }
}
