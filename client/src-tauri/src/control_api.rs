//! Bounded HTTPS transport for account sessions and signed profile bundles.

use crate::error::ClientError;
use async_trait::async_trait;
use control_protocol::account::{
    ConsumeDeviceActivationRequest, CreateDeviceSessionResponse, CreateSessionRequest,
    RefreshSessionRequest, RefreshSessionResponse, SignedProfileBundle,
};
use control_protocol::error::ErrorEnvelope;
use control_protocol::id::DeviceId;
use control_protocol::idempotency::IDEMPOTENCY_KEY_HEADER;
use control_protocol::secret::Secret;
use futures_util::StreamExt as _;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, ETAG, IF_NONE_MATCH};
use reqwest::{Method, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

const REQUEST_ID_HEADER: &str = "x-request-id";
const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Conditional bundle response returned by Control.
#[derive(Debug, Clone)]
pub enum BundleFetch {
    /// Existing active generation remains current.
    NotModified,
    /// New signed envelope and optional entity tag.
    Modified {
        /// Untrusted envelope; callers must verify it before use or persistence.
        bundle: Box<SignedProfileBundle>,
        /// Bounded opaque cache validator.
        etag: Option<String>,
    },
}

/// Transport-independent Control methods consumed by the account-first backend.
#[async_trait]
pub trait ControlPlane: Send + Sync {
    /// Consumes a one-time activation.
    async fn activate_device(
        &self,
        request: &ConsumeDeviceActivationRequest,
    ) -> Result<CreateDeviceSessionResponse, ClientError>;

    /// Creates an optional password-backed device session.
    async fn login_device(
        &self,
        request: &CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateDeviceSessionResponse, ClientError>;

    /// Rotates one device refresh credential exactly once per call.
    async fn refresh_session(
        &self,
        request: &RefreshSessionRequest,
        idempotency_key: &str,
    ) -> Result<RefreshSessionResponse, ClientError>;

    /// Fetches the current signed profile bundle.
    async fn fetch_profile_bundle(
        &self,
        access_token: &Secret<String>,
        etag: Option<&str>,
    ) -> Result<BundleFetch, ClientError>;

    /// Revokes the current device session.
    async fn logout_device(
        &self,
        access_token: &Secret<String>,
        device_id: DeviceId,
    ) -> Result<(), ClientError>;
}

/// Request and response safety bounds.
#[derive(Debug, Clone, Copy)]
pub struct ControlApiLimits {
    /// Complete request timeout.
    pub request_timeout: Duration,
    /// TCP/TLS establishment timeout.
    pub connect_timeout: Duration,
    /// Maximum serialized request size.
    pub max_request_bytes: usize,
    /// Maximum response size after transfer decoding.
    pub max_response_bytes: usize,
}

impl Default for ControlApiLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(5),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Production HTTPS Control client with no implicit retries or redirects.
pub struct ControlApi {
    origin: Url,
    client: reqwest::Client,
    limits: ControlApiLimits,
}

impl ControlApi {
    /// Builds an HTTPS-only client rooted at one origin.
    pub fn new(origin: Url, limits: ControlApiLimits) -> Result<Self, ClientError> {
        validate_origin(&origin)?;
        if limits.max_request_bytes == 0
            || limits.max_response_bytes == 0
            || limits.request_timeout.is_zero()
            || limits.connect_timeout.is_zero()
        {
            return Err(api_error("control_api_limits_invalid"));
        }
        let client = reqwest::Client::builder()
            .https_only(origin.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(limits.connect_timeout)
            .timeout(limits.request_timeout)
            .build()
            .map_err(|_| api_error("control_api_client_failed"))?;
        Ok(Self {
            origin,
            client,
            limits,
        })
    }

    /// Canonical origin included in device proof transcripts.
    #[must_use]
    pub fn origin(&self) -> &str {
        self.origin.as_str().trim_end_matches('/')
    }

    async fn json_request<B, R>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&Secret<String>>,
        etag: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<ApiResponse<R>, ClientError>
    where
        B: Serialize + Sync + ?Sized,
        R: DeserializeOwned,
    {
        let url = self
            .origin
            .join(path)
            .map_err(|_| api_error("control_api_url_invalid"))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUEST_ID_HEADER,
            HeaderValue::from_str(&Uuid::new_v4().to_string())
                .map_err(|_| api_error("control_api_request_id_invalid"))?,
        );
        if let Some(token) = bearer {
            let value = format!("Bearer {}", token.expose_secret());
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value)
                    .map_err(|_| api_error("control_api_token_invalid"))?,
            );
        }
        if let Some(value) = etag {
            if value.len() > 256 {
                return Err(api_error("control_api_etag_invalid"));
            }
            headers.insert(
                IF_NONE_MATCH,
                HeaderValue::from_str(value).map_err(|_| api_error("control_api_etag_invalid"))?,
            );
        }
        if let Some(value) = idempotency_key {
            insert_idempotency_header(&mut headers, value)?;
        }

        let mut request = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            let bytes =
                serde_json::to_vec(body).map_err(|_| api_error("control_api_request_invalid"))?;
            if bytes.len() > self.limits.max_request_bytes {
                return Err(api_error("control_api_request_too_large"));
            }
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        let response = request
            .send()
            .await
            .map_err(|_| api_error("control_api_unavailable"))?;
        let status = response.status();
        let response_etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 256)
            .map(str::to_owned);
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ApiResponse::NotModified);
        }
        let bytes = read_bounded(response, self.limits.max_response_bytes).await?;
        if !status.is_success() {
            return Err(parse_api_error(status, &bytes));
        }
        if status == StatusCode::NO_CONTENT {
            return Ok(ApiResponse::NoContent);
        }
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| api_error("control_api_response_invalid"))?;
        Ok(ApiResponse::Json {
            value,
            etag: response_etag,
        })
    }
}

#[async_trait]
impl ControlPlane for ControlApi {
    async fn activate_device(
        &self,
        request: &ConsumeDeviceActivationRequest,
    ) -> Result<CreateDeviceSessionResponse, ClientError> {
        request
            .validate()
            .map_err(|_| api_error("activation_request_invalid"))?;
        self.json_request(
            Method::POST,
            "/v1/device-activations/consume",
            Some(request),
            None,
            None,
            None,
        )
        .await?
        .into_json()
    }

    async fn login_device(
        &self,
        request: &CreateSessionRequest,
        idempotency_key: &str,
    ) -> Result<CreateDeviceSessionResponse, ClientError> {
        request
            .validate()
            .map_err(|_| api_error("login_request_invalid"))?;
        self.json_request(
            Method::POST,
            "/v1/sessions",
            Some(request),
            None,
            None,
            Some(idempotency_key),
        )
        .await?
        .into_json()
    }

    async fn refresh_session(
        &self,
        request: &RefreshSessionRequest,
        idempotency_key: &str,
    ) -> Result<RefreshSessionResponse, ClientError> {
        request
            .validate()
            .map_err(|_| api_error("refresh_request_invalid"))?;
        self.json_request(
            Method::POST,
            "/v1/sessions/refresh",
            Some(request),
            None,
            None,
            Some(idempotency_key),
        )
        .await?
        .into_json()
    }

    async fn fetch_profile_bundle(
        &self,
        access_token: &Secret<String>,
        etag: Option<&str>,
    ) -> Result<BundleFetch, ClientError> {
        match self
            .json_request::<(), SignedProfileBundle>(
                Method::GET,
                "/v1/me/profile-bundle",
                None,
                Some(access_token),
                etag,
                None,
            )
            .await?
        {
            ApiResponse::NotModified => Ok(BundleFetch::NotModified),
            ApiResponse::Json { value, etag } => Ok(BundleFetch::Modified {
                bundle: Box::new(value),
                etag,
            }),
            ApiResponse::NoContent => Err(api_error("control_api_response_invalid")),
        }
    }

    async fn logout_device(
        &self,
        access_token: &Secret<String>,
        device_id: DeviceId,
    ) -> Result<(), ClientError> {
        let path = format!("/v1/me/devices/{device_id}/session");
        match self
            .json_request::<(), serde_json::Value>(
                Method::DELETE,
                &path,
                None,
                Some(access_token),
                None,
                None,
            )
            .await?
        {
            ApiResponse::NoContent | ApiResponse::Json { .. } => Ok(()),
            ApiResponse::NotModified => Err(api_error("control_api_response_invalid")),
        }
    }
}

enum ApiResponse<T> {
    Json { value: T, etag: Option<String> },
    NotModified,
    NoContent,
}

impl<T> ApiResponse<T> {
    fn into_json(self) -> Result<T, ClientError> {
        match self {
            Self::Json { value, .. } => Ok(value),
            Self::NotModified | Self::NoContent => Err(api_error("control_api_response_invalid")),
        }
    }
}

async fn read_bounded(response: reqwest::Response, maximum: usize) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(api_error("control_api_response_too_large"));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| api_error("control_api_response_failed"))?;
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(api_error("control_api_response_too_large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn parse_api_error(status: StatusCode, bytes: &[u8]) -> ClientError {
    if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(bytes) {
        return ClientError::internal(
            format!("control_{}", envelope.error.code.as_str()),
            envelope.error.message,
        );
    }
    ClientError::internal(
        format!("control_http_{}", status.as_u16()),
        "The Control service rejected the request.",
    )
}

fn insert_idempotency_header(headers: &mut HeaderMap, value: &str) -> Result<(), ClientError> {
    if value.is_empty() || value.len() > 128 {
        return Err(api_error("control_api_idempotency_key_invalid"));
    }
    headers.insert(
        IDEMPOTENCY_KEY_HEADER,
        HeaderValue::from_str(value)
            .map_err(|_| api_error("control_api_idempotency_key_invalid"))?,
    );
    Ok(())
}

pub(crate) fn validate_origin(origin: &Url) -> Result<(), ClientError> {
    if !is_secure_or_loopback(origin)
        || origin.cannot_be_a_base()
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(api_error("control_api_origin_invalid"));
    }
    Ok(())
}

fn is_secure_or_loopback(origin: &Url) -> bool {
    match (origin.scheme(), origin.host()) {
        ("https", Some(_)) => true,
        ("http", Some(url::Host::Domain(host))) => host.eq_ignore_ascii_case("localhost"),
        ("http", Some(url::Host::Ipv4(address))) => address.is_loopback(),
        ("http", Some(url::Host::Ipv6(address))) => address.is_loopback(),
        _ => false,
    }
}

fn api_error(code: &str) -> ClientError {
    ClientError::internal(code, "The Control service operation failed.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_clean_https_or_loopback_origin() {
        assert!(ControlApi::new(
            Url::parse("https://control.example/").unwrap(),
            ControlApiLimits::default()
        )
        .is_ok());
        assert!(ControlApi::new(
            Url::parse("http://127.0.0.1:8787/").unwrap(),
            ControlApiLimits::default()
        )
        .is_ok());
        for origin in [
            "http://control.example/",
            "http://192.0.2.1/",
            "https://user@control.example/",
            "https://control.example/?debug=true",
        ] {
            assert!(
                ControlApi::new(Url::parse(origin).unwrap(), ControlApiLimits::default()).is_err()
            );
        }
    }

    #[test]
    fn rejects_zero_or_unbounded_by_construction_limits() {
        let limits = ControlApiLimits {
            max_response_bytes: 0,
            ..ControlApiLimits::default()
        };
        assert!(ControlApi::new(Url::parse("https://control.example/").unwrap(), limits).is_err());
    }

    #[test]
    fn inserts_bounded_idempotency_header() {
        let mut headers = HeaderMap::new();
        insert_idempotency_header(&mut headers, "operation-1").unwrap();
        assert_eq!(
            headers
                .get(IDEMPOTENCY_KEY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("operation-1")
        );
        assert!(insert_idempotency_header(&mut headers, "").is_err());
    }
}
