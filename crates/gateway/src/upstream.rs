use async_trait::async_trait;
use std::sync::Mutex;

use crate::ApiError;

pub struct Outbound {
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub header_name: String,
    pub header_value: String,
}

pub struct Inbound {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait Upstream: Send + Sync {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError>;
}

/// Test double that records the injected header and returns a fixed body.
pub struct RecordingUpstream {
    pub last_header: Mutex<Option<(String, String)>>,
}

impl RecordingUpstream {
    pub fn new() -> Self {
        Self {
            last_header: Mutex::new(None),
        }
    }

    pub fn last_value(&self) -> Option<String> {
        self.last_header
            .lock()
            .expect("upstream lock")
            .as_ref()
            .map(|(_, value)| value.clone())
    }
}

impl Default for RecordingUpstream {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Upstream for RecordingUpstream {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError> {
        *self.last_header.lock().expect("upstream lock") =
            Some((request.header_name, request.header_value));
        Ok(Inbound {
            status: 200,
            body: b"upstream-ok".to_vec(),
        })
    }
}

/// HTTPS client for proxy injection.
///
/// The scheme must be `https`. Redirects are not followed. The secret header
/// replaces any previous value and is not copied onto the response.
pub struct HttpUpstream {
    client: reqwest::Client,
}

impl HttpUpstream {
    pub fn new() -> Result<Self, ApiError> {
        Self::build(false)
    }

    /// Trusts any certificate. Tests use this against a local server.
    /// `cargo run` uses [`HttpUpstream::new`].
    pub fn new_insecure() -> Result<Self, ApiError> {
        Self::build(true)
    }

    fn build(insecure: bool) -> Result<Self, ApiError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(|_| ApiError::UpstreamFailed)?;
        Ok(Self { client })
    }
}

impl Default for HttpUpstream {
    fn default() -> Self {
        Self::new().expect("https client")
    }
}

#[async_trait]
impl Upstream for HttpUpstream {
    async fn forward(&self, request: Outbound) -> Result<Inbound, ApiError> {
        let url = url::Url::parse(&request.url).map_err(|_| ApiError::UpstreamFailed)?;
        if url.scheme() != "https" {
            return Err(ApiError::UpstreamFailed);
        }
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| ApiError::UpstreamFailed)?;
        let name = reqwest::header::HeaderName::from_bytes(request.header_name.as_bytes())
            .map_err(|_| ApiError::UpstreamFailed)?;
        let value = reqwest::header::HeaderValue::from_str(&request.header_value)
            .map_err(|_| ApiError::UpstreamFailed)?;
        let response = self
            .client
            .request(method, url)
            .header(name, value)
            .body(request.body)
            .send()
            .await
            .map_err(|_| ApiError::UpstreamFailed)?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|_| ApiError::UpstreamFailed)?
            .to_vec();
        Ok(Inbound { status, body })
    }
}

/// Kept so a test can still force an upstream failure. `cargo run` uses [`HttpUpstream`].
pub struct UnconfiguredUpstream;

#[async_trait]
impl Upstream for UnconfiguredUpstream {
    async fn forward(&self, _request: Outbound) -> Result<Inbound, ApiError> {
        Err(ApiError::UpstreamFailed)
    }
}
