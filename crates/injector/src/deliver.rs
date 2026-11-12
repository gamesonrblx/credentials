//! Delivery of an opened secret under a verified grant.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::grant::{safe_header_text, GrantDelivery, HttpMethod, VerifiedGrant};
use crate::json::{handoff_json, sha256_hex};
use crate::InjectorError;

/// Largest upstream response body the injector returns.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const CONNECT_TIMEOUT_SECS: u64 = 5;
pub const TOTAL_TIMEOUT_SECS: u64 = 30;

/// The one request a proxy grant allows. `header_value` holds the secret.
pub struct Outbound {
    pub method: HttpMethod,
    pub url: Url,
    pub header_name: String,
    pub header_value: Zeroizing<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for Outbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Outbound")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .field("header_name", &self.header_name)
            .field("header_value", &"<redacted>")
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Status and body from the upstream.
pub struct UpstreamResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Sends the proxy request. Tests substitute a recorder.
///
/// An implementation must not follow redirects and should stop reading the
/// body once it passes [`MAX_RESPONSE_BYTES`]. [`deliver`] checks the cap again.
pub trait Transport {
    fn send(
        &self,
        request: Outbound,
    ) -> impl Future<Output = Result<UpstreamResponse, InjectorError>> + Send;
}

/// HTTPS transport: no redirects, 5 s connect timeout, 30 s total timeout,
/// and a streamed body capped at [`MAX_RESPONSE_BYTES`].
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    pub fn new() -> Result<Self, InjectorError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(TOTAL_TIMEOUT_SECS))
            .build()
            .map_err(|_| InjectorError::Transport)?;
        Ok(Self { client })
    }
}

impl Transport for ReqwestTransport {
    async fn send(&self, request: Outbound) -> Result<UpstreamResponse, InjectorError> {
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };
        let name = reqwest::header::HeaderName::from_bytes(request.header_name.as_bytes())
            .map_err(|_| InjectorError::HeaderValue)?;
        let mut value = reqwest::header::HeaderValue::from_bytes(request.header_value.as_bytes())
            .map_err(|_| InjectorError::HeaderValue)?;
        value.set_sensitive(true);
        let mut builder = self.client.request(method, request.url).header(name, value);
        if let Some(content_type) = &request.content_type {
            let content_type = reqwest::header::HeaderValue::from_str(content_type)
                .map_err(|_| InjectorError::HeaderValue)?;
            builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        let mut response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|_| InjectorError::Transport)?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| InjectorError::Transport)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                body.zeroize();
                return Err(InjectorError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(UpstreamResponse { status, body })
    }
}

/// Upstream result of a proxy delivery. The secret is not in it.
pub struct ProxyResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl fmt::Debug for ProxyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// A formatted header for a local runner. Holds plaintext.
pub struct HeaderHandoff {
    pub header_name: String,
    pub value: Zeroizing<String>,
}

impl HeaderHandoff {
    /// `{"header_name":...,"value":...}` in a buffer wiped on drop.
    pub fn to_json(&self) -> Zeroizing<String> {
        handoff_json("header_name", &self.header_name, &self.value)
    }
}

impl fmt::Debug for HeaderHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderHandoff")
            .field("header_name", &self.header_name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// An environment variable for a local runner. Holds plaintext.
pub struct EnvHandoff {
    pub env_name: String,
    pub value: Zeroizing<String>,
}

impl EnvHandoff {
    /// `{"env_name":...,"value":...}` in a buffer wiped on drop.
    pub fn to_json(&self) -> Zeroizing<String> {
        handoff_json("env_name", &self.env_name, &self.value)
    }
}

impl fmt::Debug for EnvHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvHandoff")
            .field("env_name", &self.env_name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Result of [`deliver`].
#[derive(Debug)]
pub enum Delivered {
    Proxy(ProxyResponse),
    Header(HeaderHandoff),
    Env(EnvHandoff),
}

/// Open the grant's ciphertext and perform the delivery it authorises.
///
/// Proxy: the injector sends the one request the grant names, with the secret
/// in one header, and returns only the upstream status and body. `body` must
/// hash to the grant's `body_sha256`. A response that contains the secret or
/// the formatted header is refused.
///
/// Header and env: the plaintext is returned to the caller for a local
/// hand-off. These are the only paths where plaintext leaves this function.
/// `body` must be empty for them.
pub async fn deliver<T: Transport>(
    grant: &VerifiedGrant,
    decapsulation_key: &[u8; 32],
    body: &[u8],
    transport: &T,
) -> Result<Delivered, InjectorError> {
    match &grant.delivery {
        GrantDelivery::Proxy(policy) => {
            if sha256_hex(body) != policy.body_sha256 {
                return Err(InjectorError::BodyMismatch);
            }
            let secret = grant.open(decapsulation_key)?;
            let header_value = format_header(&policy.header_format, &secret)?;
            let outbound = Outbound {
                method: policy.method,
                url: policy.url.clone(),
                header_name: policy.header_name.clone(),
                header_value: header_value.clone(),
                content_type: policy.content_type.clone(),
                body: body.to_vec(),
            };
            let mut response = transport.send(outbound).await?;
            if response.body.len() > MAX_RESPONSE_BYTES {
                response.body.zeroize();
                return Err(InjectorError::ResponseTooLarge);
            }
            if contains(&response.body, &secret)
                || contains(&response.body, header_value.as_bytes())
            {
                response.body.zeroize();
                return Err(InjectorError::Reflected);
            }
            Ok(Delivered::Proxy(ProxyResponse {
                status: response.status,
                body: response.body,
            }))
        }
        GrantDelivery::Header {
            header_name,
            header_format,
        } => {
            if !body.is_empty() {
                return Err(InjectorError::Policy);
            }
            let secret = grant.open(decapsulation_key)?;
            Ok(Delivered::Header(HeaderHandoff {
                header_name: header_name.clone(),
                value: format_header(header_format, &secret)?,
            }))
        }
        GrantDelivery::Env { env_name } => {
            if !body.is_empty() {
                return Err(InjectorError::Policy);
            }
            let secret = grant.open(decapsulation_key)?;
            let text = std::str::from_utf8(&secret).map_err(|_| InjectorError::HeaderValue)?;
            if text.contains('\0') {
                return Err(InjectorError::HeaderValue);
            }
            Ok(Delivered::Env(EnvHandoff {
                env_name: env_name.clone(),
                value: Zeroizing::new(text.to_owned()),
            }))
        }
    }
}

/// Replace `{value}` once. The secret must be UTF-8 and the result must not
/// contain CR, LF, NUL, or another control character except tab.
fn format_header(format: &str, secret: &[u8]) -> Result<Zeroizing<String>, InjectorError> {
    let secret = std::str::from_utf8(secret).map_err(|_| InjectorError::HeaderValue)?;
    if !safe_header_text(secret) || !safe_header_text(format) {
        return Err(InjectorError::HeaderValue);
    }
    let (head, tail) = format
        .split_once("{value}")
        .ok_or(InjectorError::HeaderValue)?;
    if tail.contains("{value}") {
        return Err(InjectorError::HeaderValue);
    }
    let mut out = Zeroizing::new(String::with_capacity(
        head.len() + secret.len() + tail.len(),
    ));
    out.push_str(head);
    out.push_str(secret);
    out.push_str(tail);
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
