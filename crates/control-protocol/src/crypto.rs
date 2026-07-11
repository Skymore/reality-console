//! Encoded public cryptographic values carried by the protocol.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// Failure to parse a protocol cryptographic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEncodedValue(&'static str);

impl fmt::Display for InvalidEncodedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for InvalidEncodedValue {}

fn decode_exact(value: &str, expected_length: usize) -> Result<(), InvalidEncodedValue> {
    if value.contains('=') {
        return Err(InvalidEncodedValue(
            "expected unpadded base64url without whitespace",
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| InvalidEncodedValue("expected unpadded base64url without whitespace"))?;
    if decoded.len() != expected_length {
        return Err(InvalidEncodedValue("encoded value has an invalid length"));
    }
    Ok(())
}

macro_rules! fixed_base64url {
    ($(#[$meta:meta])* $name:ident, $length:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Returns the unpadded base64url representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = InvalidEncodedValue;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                decode_exact(value, $length)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
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

fixed_base64url!(/// An Ed25519 public key encoded as 32 unpadded base64url bytes.
    Ed25519PublicKey, 32);
fixed_base64url!(/// An X25519 public key encoded as 32 unpadded base64url bytes.
    X25519PublicKey, 32);
fixed_base64url!(/// An Ed25519 signature encoded as 64 unpadded base64url bytes.
    Ed25519Signature, 64);

/// A SHA-256 digest encoded as `sha256:` followed by lowercase hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Creates the canonical wire representation from raw SHA-256 bytes.
    #[must_use]
    pub fn from_bytes(value: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut encoded = String::with_capacity(71);
        encoded.push_str("sha256:");
        for byte in value {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(encoded)
    }

    /// Returns the canonical digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Sha256Digest {
    type Err = InvalidEncodedValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(InvalidEncodedValue("expected a sha256: digest"));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(InvalidEncodedValue(
                "SHA-256 digest must use 64 lowercase hexadecimal characters",
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// A fresh 128- to 512-bit nonce encoded as unpadded base64url.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(String);

impl Nonce {
    /// Returns the encoded nonce.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Nonce {
    type Err = InvalidEncodedValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.contains('=') {
            return Err(InvalidEncodedValue(
                "expected unpadded base64url without whitespace",
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| InvalidEncodedValue("expected unpadded base64url without whitespace"))?;
        if !(16..=64).contains(&decoded.len()) {
            return Err(InvalidEncodedValue(
                "nonce must contain between 16 and 64 bytes",
            ));
        }
        Ok(Self(value.to_owned()))
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519PublicKey, Ed25519Signature, Nonce};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    #[test]
    fn encoded_values_enforce_algorithm_lengths() {
        let public_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let signature = URL_SAFE_NO_PAD.encode([9_u8; 64]);
        let nonce = URL_SAFE_NO_PAD.encode([1_u8; 16]);

        assert!(public_key.parse::<Ed25519PublicKey>().is_ok());
        assert!(signature.parse::<Ed25519Signature>().is_ok());
        assert!(nonce.parse::<Nonce>().is_ok());
        assert!(URL_SAFE_NO_PAD
            .encode([1_u8; 31])
            .parse::<Ed25519PublicKey>()
            .is_err());
    }
}
