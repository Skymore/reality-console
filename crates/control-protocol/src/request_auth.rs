//! Canonical signed-node-request authentication values and transcripts.
//!
//! HTTP adapters are responsible for extracting exactly one value for each
//! authentication header. This module validates those values and signs an
//! origin-form request target without performing transport-specific parsing.

use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce, Sha256Digest};
use crate::id::{ControllerInstanceId, NodeId, NodeKeyId, Timestamp};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

const REQUEST_DOMAIN: &[u8] = b"control/node-request/v1";
const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;
const MIN_NONCE_ENCODED_BYTES: usize = 22;
const MAX_NONCE_ENCODED_BYTES: usize = 86;
const SIGNATURE_ENCODED_BYTES: usize = 86;

/// HTTP methods accepted by the signed node API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRequestMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl NodeRequestMethod {
    /// Returns the canonical uppercase wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

impl fmt::Display for NodeRequestMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for NodeRequestMethod {
    type Err = NodeRequestAuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "PATCH" => Ok(Self::Patch),
            "DELETE" => Ok(Self::Delete),
            _ => Err(NodeRequestAuthError::UnsupportedMethod),
        }
    }
}

/// A canonical origin-form path with an optional canonical raw query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedPathAndQuery(String);

impl NormalizedPathAndQuery {
    /// Returns the exact request target covered by the signature.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NormalizedPathAndQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for NormalizedPathAndQuery {
    type Err = NodeRequestAuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_path_and_query(value)?;
        Ok(Self(value.to_owned()))
    }
}

/// Validated values carried by the five signed-node-request headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRequestAuthHeaders {
    node_id: NodeId,
    key_id: NodeKeyId,
    timestamp: Timestamp,
    nonce: Nonce,
    signature: Ed25519Signature,
}

impl NodeRequestAuthHeaders {
    /// Creates headers from already validated protocol values.
    #[must_use]
    pub const fn new(
        node_id: NodeId,
        key_id: NodeKeyId,
        timestamp: Timestamp,
        nonce: Nonce,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            node_id,
            key_id,
            timestamp,
            nonce,
            signature,
        }
    }

    /// Validates the five raw header values without parsing an HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`NodeRequestAuthError::InvalidHeader`] for a malformed or
    /// non-canonical value.
    pub fn parse(
        node_id: &str,
        key_id: &str,
        timestamp: &str,
        nonce: &str,
        signature: &str,
    ) -> Result<Self, NodeRequestAuthError> {
        let node_id = node_id
            .parse()
            .map_err(|_| NodeRequestAuthError::InvalidHeader("X-Node-Id"))?;
        let key_id = key_id
            .parse()
            .map_err(|_| NodeRequestAuthError::InvalidHeader("X-Node-Key-Id"))?;
        let parsed_timestamp: Timestamp = timestamp
            .parse()
            .map_err(|_| NodeRequestAuthError::InvalidHeader("X-Node-Timestamp"))?;
        if parsed_timestamp.to_string() != timestamp {
            return Err(NodeRequestAuthError::InvalidHeader("X-Node-Timestamp"));
        }
        if !(MIN_NONCE_ENCODED_BYTES..=MAX_NONCE_ENCODED_BYTES).contains(&nonce.len()) {
            return Err(NodeRequestAuthError::InvalidHeader("X-Node-Nonce"));
        }
        if signature.len() != SIGNATURE_ENCODED_BYTES {
            return Err(NodeRequestAuthError::InvalidHeader("X-Node-Signature"));
        }
        let nonce = parse_canonical_base64url(nonce, "X-Node-Nonce")?;
        let signature = parse_canonical_base64url(signature, "X-Node-Signature")?;

        Ok(Self::new(
            node_id,
            key_id,
            parsed_timestamp,
            nonce,
            signature,
        ))
    }

    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    #[must_use]
    pub const fn key_id(&self) -> NodeKeyId {
        self.key_id
    }

    #[must_use]
    pub const fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

/// Canonical request fields that are independent of authentication headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRequestSigningInput {
    method: NodeRequestMethod,
    path_and_query: NormalizedPathAndQuery,
    body_digest: Sha256Digest,
}

impl NodeRequestSigningInput {
    /// Validates canonical method, request target, and digest strings.
    ///
    /// # Errors
    ///
    /// Rejects unsupported methods, non-origin or non-canonical request
    /// targets, and malformed SHA-256 digests.
    pub fn parse(
        method: &str,
        path_and_query: &str,
        body_digest: &str,
    ) -> Result<Self, NodeRequestAuthError> {
        Ok(Self {
            method: method.parse()?,
            path_and_query: path_and_query.parse()?,
            body_digest: body_digest
                .parse()
                .map_err(|_| NodeRequestAuthError::InvalidBodyDigest)?,
        })
    }

    /// Builds signing input and computes the digest from the exact body bytes.
    ///
    /// # Errors
    ///
    /// Rejects unsupported methods and non-origin or non-canonical request
    /// targets.
    pub fn from_body(
        method: &str,
        path_and_query: &str,
        body: &[u8],
    ) -> Result<Self, NodeRequestAuthError> {
        Ok(Self {
            method: method.parse()?,
            path_and_query: path_and_query.parse()?,
            body_digest: sha256_digest(body),
        })
    }

    #[must_use]
    pub const fn method(&self) -> NodeRequestMethod {
        self.method
    }

    #[must_use]
    pub const fn path_and_query(&self) -> &NormalizedPathAndQuery {
        &self.path_and_query
    }

    #[must_use]
    pub const fn body_digest(&self) -> &Sha256Digest {
        &self.body_digest
    }

    /// Builds the deterministic version 1 transcript.
    ///
    /// Node and key ownership are intentionally verified by the service before
    /// this step; the protocol specification binds the request fields below.
    ///
    /// # Errors
    ///
    /// Returns [`NodeRequestAuthError::FieldTooLarge`] if a field does not fit
    /// the version 1 length-prefix encoding.
    pub fn transcript(
        &self,
        timestamp: Timestamp,
        nonce: &Nonce,
        controller_instance_id: ControllerInstanceId,
    ) -> Result<Vec<u8>, NodeRequestAuthError> {
        let mut transcript = Transcript::new(REQUEST_DOMAIN)?;
        transcript.text("method", self.method.as_str())?;
        transcript.text("path-and-query", self.path_and_query.as_str())?;
        transcript.text("timestamp", &timestamp.to_string())?;
        transcript.text("nonce", nonce.as_str())?;
        transcript.bytes("body-sha256", &decode_digest(&self.body_digest)?)?;
        transcript.text(
            "controller-instance-id",
            &controller_instance_id.to_string(),
        )?;
        Ok(transcript.finish())
    }
}

/// Computes the protocol's canonical body digest.
#[must_use]
pub fn sha256_digest(body: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(body).into())
}

/// Verifies the request signature over the canonical transcript.
///
/// The caller must separately verify that the header node owns the supplied
/// key, that the key is active, and that timestamp/nonce replay policy passes.
///
/// # Errors
///
/// Returns [`NodeRequestAuthError::SignatureInvalid`] for invalid key material
/// or a signature mismatch, and [`NodeRequestAuthError::FieldTooLarge`] if the
/// transcript cannot be represented.
pub fn verify_node_request_signature(
    public_key: &Ed25519PublicKey,
    headers: &NodeRequestAuthHeaders,
    input: &NodeRequestSigningInput,
    controller_instance_id: ControllerInstanceId,
) -> Result<(), NodeRequestAuthError> {
    let public_bytes = decode_exact::<32>(public_key.as_str())?;
    let signature_bytes = decode_exact::<64>(headers.signature.as_str())?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| NodeRequestAuthError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let transcript = input.transcript(headers.timestamp, &headers.nonce, controller_instance_id)?;
    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| NodeRequestAuthError::SignatureInvalid)
}

fn parse_canonical_base64url<T>(
    value: &str,
    header: &'static str,
) -> Result<T, NodeRequestAuthError>
where
    T: FromStr,
{
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| NodeRequestAuthError::InvalidHeader(header))?;
    if URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err(NodeRequestAuthError::InvalidHeader(header));
    }
    value
        .parse()
        .map_err(|_| NodeRequestAuthError::InvalidHeader(header))
}

fn decode_digest(value: &Sha256Digest) -> Result<[u8; 32], NodeRequestAuthError> {
    let hex = value
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(NodeRequestAuthError::InvalidBodyDigest)?;
    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (decode_hex(pair[0]).ok_or(NodeRequestAuthError::InvalidBodyDigest)? << 4)
            | decode_hex(pair[1]).ok_or(NodeRequestAuthError::InvalidBodyDigest)?;
    }
    Ok(bytes)
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], NodeRequestAuthError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| NodeRequestAuthError::SignatureInvalid)?
        .try_into()
        .map_err(|_| NodeRequestAuthError::SignatureInvalid)
}

fn validate_path_and_query(value: &str) -> Result<(), NodeRequestAuthError> {
    if value.len() > MAX_REQUEST_TARGET_BYTES {
        return Err(NodeRequestAuthError::InvalidRequestTarget(
            "request target exceeds the protocol bound",
        ));
    }
    if value.contains('#') {
        return Err(NodeRequestAuthError::InvalidRequestTarget(
            "fragments are not allowed",
        ));
    }
    if !value.starts_with('/') || value.starts_with("//") {
        return Err(NodeRequestAuthError::InvalidRequestTarget(
            "expected an origin-form path",
        ));
    }

    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(path, query)| (path, Some(query)));
    validate_uri_component(path, false)?;
    if path != "/" && path.contains("//") {
        return Err(NodeRequestAuthError::InvalidRequestTarget(
            "repeated path separators are not canonical",
        ));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(NodeRequestAuthError::InvalidRequestTarget(
            "dot path segments are not canonical",
        ));
    }

    if let Some(query) = query {
        if query.is_empty() {
            return Err(NodeRequestAuthError::InvalidRequestTarget(
                "an empty query marker is not canonical",
            ));
        }
        validate_uri_component(query, true)?;
        if query.starts_with('&') || query.ends_with('&') || query.contains("&&") {
            return Err(NodeRequestAuthError::InvalidRequestTarget(
                "empty query components are not canonical",
            ));
        }
        if query.contains('+') {
            return Err(NodeRequestAuthError::InvalidRequestTarget(
                "query spaces must use percent encoding",
            ));
        }
    }
    Ok(())
}

fn validate_uri_component(value: &str, query: bool) -> Result<(), NodeRequestAuthError> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let Some(encoded) = bytes.get(index + 1..index + 3) else {
                return Err(NodeRequestAuthError::InvalidRequestTarget(
                    "percent encoding is incomplete",
                ));
            };
            if !encoded.iter().all(u8::is_ascii_hexdigit)
                || encoded.iter().any(|byte| (b'a'..=b'f').contains(byte))
            {
                return Err(NodeRequestAuthError::InvalidRequestTarget(
                    "percent encoding must use uppercase hexadecimal",
                ));
            }
            let decoded = (decode_hex_upper(encoded[0]) << 4) | decode_hex_upper(encoded[1]);
            if is_unreserved(decoded) {
                return Err(NodeRequestAuthError::InvalidRequestTarget(
                    "unreserved characters must not be percent encoded",
                ));
            }
            if !query && matches!(decoded, b'/' | b'\\' | b'?' | b'#') {
                return Err(NodeRequestAuthError::InvalidRequestTarget(
                    "encoded path separators are not canonical",
                ));
            }
            index += 3;
            continue;
        }
        if !byte.is_ascii() || !is_uri_character(byte, query) {
            return Err(NodeRequestAuthError::InvalidRequestTarget(
                "request target contains a non-canonical character",
            ));
        }
        index += 1;
    }
    Ok(())
}

const fn is_unreserved(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')
}

const fn is_uri_character(value: u8, query: bool) -> bool {
    is_unreserved(value)
        || matches!(
            value,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
        || (query && value == b'?')
}

const fn decode_hex_upper(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn new(domain: &[u8]) -> Result<Self, NodeRequestAuthError> {
        let mut transcript = Self { bytes: Vec::new() };
        transcript.bytes("domain", domain)?;
        Ok(transcript)
    }

    fn text(&mut self, label: &str, value: &str) -> Result<(), NodeRequestAuthError> {
        self.bytes(label, value.as_bytes())
    }

    fn bytes(&mut self, label: &str, value: &[u8]) -> Result<(), NodeRequestAuthError> {
        let label_length =
            u16::try_from(label.len()).map_err(|_| NodeRequestAuthError::FieldTooLarge)?;
        let value_length =
            u32::try_from(value.len()).map_err(|_| NodeRequestAuthError::FieldTooLarge)?;
        self.bytes.extend_from_slice(&label_length.to_be_bytes());
        self.bytes.extend_from_slice(label.as_bytes());
        self.bytes.extend_from_slice(&value_length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Failure to validate or verify signed node-request authentication.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NodeRequestAuthError {
    #[error("unsupported signed node request method")]
    UnsupportedMethod,
    #[error("invalid signed node request target: {0}")]
    InvalidRequestTarget(&'static str),
    #[error("invalid signed node request body digest")]
    InvalidBodyDigest,
    #[error("invalid {0} header")]
    InvalidHeader(&'static str),
    #[error("signed node request transcript field is too large")]
    FieldTooLarge,
    #[error("signed node request signature is invalid")]
    SignatureInvalid,
}

#[cfg(test)]
mod tests {
    use super::{
        sha256_digest, verify_node_request_signature, NodeRequestAuthError, NodeRequestAuthHeaders,
        NodeRequestMethod, NodeRequestSigningInput, NormalizedPathAndQuery,
    };
    use crate::crypto::{Ed25519PublicKey, Ed25519Signature, Nonce};
    use crate::id::{ControllerInstanceId, NodeId, NodeKeyId, Timestamp};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};

    const NODE_ID: &str = "2024545a-8b5c-4a8f-ae11-e12152ee3233";
    const KEY_ID: &str = "af3b6f7c-e63a-4428-9745-66553fb410a6";
    const CONTROLLER_ID: &str = "3dd2e61c-2039-4993-b31d-881c6a1ba81f";
    const TIMESTAMP: &str = "2026-07-11T20:15:30Z";

    fn nonce(byte: u8) -> Nonce {
        URL_SAFE_NO_PAD.encode([byte; 16]).parse().unwrap()
    }

    fn signature(byte: u8) -> Ed25519Signature {
        URL_SAFE_NO_PAD.encode([byte; 64]).parse().unwrap()
    }

    fn unsigned_headers() -> NodeRequestAuthHeaders {
        NodeRequestAuthHeaders::new(
            NODE_ID.parse().unwrap(),
            KEY_ID.parse().unwrap(),
            TIMESTAMP.parse().unwrap(),
            nonce(3),
            signature(0),
        )
    }

    #[test]
    fn parses_only_canonical_header_values() {
        let nonce = URL_SAFE_NO_PAD.encode([3_u8; 16]);
        let signature = URL_SAFE_NO_PAD.encode([4_u8; 64]);
        let headers =
            NodeRequestAuthHeaders::parse(NODE_ID, KEY_ID, TIMESTAMP, &nonce, &signature).unwrap();

        assert_eq!(headers.node_id(), NODE_ID.parse::<NodeId>().unwrap());
        assert_eq!(headers.key_id(), KEY_ID.parse::<NodeKeyId>().unwrap());
        assert_eq!(headers.timestamp(), TIMESTAMP.parse::<Timestamp>().unwrap());
        assert_eq!(headers.nonce().as_str(), nonce);
        assert_eq!(headers.signature().as_str(), signature);

        assert!(NodeRequestAuthHeaders::parse(
            &NODE_ID.to_uppercase(),
            KEY_ID,
            TIMESTAMP,
            &nonce,
            &signature,
        )
        .is_err());
        assert!(NodeRequestAuthHeaders::parse(
            NODE_ID,
            KEY_ID,
            TIMESTAMP,
            &"A".repeat(1_000_000),
            &signature,
        )
        .is_err());
        assert!(NodeRequestAuthHeaders::parse(
            NODE_ID,
            KEY_ID,
            "2026-07-11T13:15:30-07:00",
            &nonce,
            &signature,
        )
        .is_err());
        assert!(NodeRequestAuthHeaders::parse(
            NODE_ID,
            KEY_ID,
            TIMESTAMP,
            "not-base64",
            &signature,
        )
        .is_err());
    }

    #[test]
    fn methods_are_explicit_and_canonical() {
        assert_eq!("POST".parse(), Ok(NodeRequestMethod::Post));
        for invalid in ["post", "HEAD", "OPTIONS", "CONNECT", "TRACE", ""] {
            assert_eq!(
                invalid.parse::<NodeRequestMethod>(),
                Err(NodeRequestAuthError::UnsupportedMethod)
            );
        }
    }

    #[test]
    fn request_targets_reject_ambiguous_or_non_canonical_forms() {
        for valid in [
            "/v1/nodes/2024545a/heartbeat",
            "/v1/state?after=12&wait=30",
            "/v1/search?cursor=a%2Fb&filter=x%20y",
            "/",
        ] {
            assert!(valid.parse::<NormalizedPathAndQuery>().is_ok(), "{valid}");
        }

        for invalid in [
            "https://control.example/v1/state",
            "//control.example/v1/state",
            "v1/state",
            "/v1/state#fragment",
            "/v1//state",
            "/v1/./state",
            "/v1/../state",
            "/v1/%73tate",
            "/v1/%2fstate",
            "/v1/%2Fstate",
            "/v1/state?",
            "/v1/state?&wait=1",
            "/v1/state?wait=1&&after=2",
            "/v1/state?q=a+b",
            "/v1/state?q=white space",
            "/v1/状态",
        ] {
            assert!(
                invalid.parse::<NormalizedPathAndQuery>().is_err(),
                "{invalid}"
            );
        }
        assert!(format!("/{}", "a".repeat(8 * 1024))
            .parse::<NormalizedPathAndQuery>()
            .is_err());
    }

    #[test]
    fn body_digest_is_exact_and_validated() {
        assert_eq!(
            sha256_digest(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            NodeRequestSigningInput::parse("POST", "/v1/state", "sha256:xyz"),
            Err(NodeRequestAuthError::InvalidBodyDigest)
        );
    }

    #[test]
    fn transcript_and_signature_match_fixed_vector() {
        let input = NodeRequestSigningInput::from_body(
            "POST",
            "/v1/nodes/2024545a/heartbeat?full=true",
            br#"{"state":"serving"}"#,
        )
        .unwrap();
        let headers = unsigned_headers();
        let controller_id: ControllerInstanceId = CONTROLLER_ID.parse().unwrap();
        let transcript = input
            .transcript(headers.timestamp(), headers.nonce(), controller_id)
            .unwrap();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let signed = signing_key.sign(&transcript);

        assert_eq!(
            URL_SAFE_NO_PAD.encode(&transcript),
            "AAZkb21haW4AAAAXY29udHJvbC9ub2RlLXJlcXVlc3QvdjEABm1ldGhvZAAAAARQT1NUAA5wYXRoLWFuZC1xdWVyeQAAACYvdjEvbm9kZXMvMjAyNDU0NWEvaGVhcnRiZWF0P2Z1bGw9dHJ1ZQAJdGltZXN0YW1wAAAAFDIwMjYtMDctMTFUMjA6MTU6MzBaAAVub25jZQAAABZBd01EQXdNREF3TURBd01EQXdNREF3AAtib2R5LXNoYTI1NgAAACDCGo-tR4iXClTQeAp2OnXiIljQY0FBJ6AAchjDKggUPAAWY29udHJvbGxlci1pbnN0YW5jZS1pZAAAACQzZGQyZTYxYy0yMDM5LTQ5OTMtYjMxZC04ODFjNmExYmE4MWY"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(signed.to_bytes()),
            "l_awjC-ho-bhk0qLskBzvNaqRLqBDS8ysPSdB9E27UfDwD0twFhYufeJzIVhtZRzloWfT8GmygwpXmy7YK6iDQ"
        );
    }

    #[test]
    fn verification_rejects_every_signed_field_substitution() {
        let original = NodeRequestSigningInput::from_body(
            "POST",
            "/v1/nodes/2024545a/heartbeat?full=true",
            b"payload",
        )
        .unwrap();
        let controller_id: ControllerInstanceId = CONTROLLER_ID.parse().unwrap();
        let timestamp: Timestamp = TIMESTAMP.parse().unwrap();
        let original_nonce = nonce(3);
        let transcript = original
            .transcript(timestamp, &original_nonce, controller_id)
            .unwrap();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key: Ed25519PublicKey = URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().to_bytes())
            .parse()
            .unwrap();
        let signed: Ed25519Signature = URL_SAFE_NO_PAD
            .encode(signing_key.sign(&transcript).to_bytes())
            .parse()
            .unwrap();
        let headers = NodeRequestAuthHeaders::new(
            NODE_ID.parse().unwrap(),
            KEY_ID.parse().unwrap(),
            timestamp,
            original_nonce,
            signed,
        );

        assert!(
            verify_node_request_signature(&public_key, &headers, &original, controller_id).is_ok()
        );

        let substitutions = [
            NodeRequestSigningInput::from_body(
                "GET",
                "/v1/nodes/2024545a/heartbeat?full=true",
                b"payload",
            )
            .unwrap(),
            NodeRequestSigningInput::from_body(
                "POST",
                "/v1/nodes/2024545b/heartbeat?full=true",
                b"payload",
            )
            .unwrap(),
            NodeRequestSigningInput::from_body(
                "POST",
                "/v1/nodes/2024545a/heartbeat?full=false",
                b"payload",
            )
            .unwrap(),
            NodeRequestSigningInput::from_body(
                "POST",
                "/v1/nodes/2024545a/heartbeat?full=true",
                b"changed",
            )
            .unwrap(),
        ];
        for substitution in substitutions {
            assert_eq!(
                verify_node_request_signature(&public_key, &headers, &substitution, controller_id),
                Err(NodeRequestAuthError::SignatureInvalid)
            );
        }

        let changed_timestamp = NodeRequestAuthHeaders::new(
            headers.node_id(),
            headers.key_id(),
            "2026-07-11T20:15:31Z".parse().unwrap(),
            headers.nonce().clone(),
            headers.signature().clone(),
        );
        assert!(verify_node_request_signature(
            &public_key,
            &changed_timestamp,
            &original,
            controller_id
        )
        .is_err());

        let changed_nonce = NodeRequestAuthHeaders::new(
            headers.node_id(),
            headers.key_id(),
            headers.timestamp(),
            nonce(4),
            headers.signature().clone(),
        );
        assert!(verify_node_request_signature(
            &public_key,
            &changed_nonce,
            &original,
            controller_id
        )
        .is_err());

        let changed_controller: ControllerInstanceId =
            "8e2f355b-53d8-4c2a-9835-1a3ff6b1f527".parse().unwrap();
        assert!(verify_node_request_signature(
            &public_key,
            &headers,
            &original,
            changed_controller
        )
        .is_err());
    }
}
