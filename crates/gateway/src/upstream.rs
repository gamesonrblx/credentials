use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use crate::policy::method_allowed;
use crate::ApiError;

/// Time allowed to open the TCP and TLS connection to the upstream.
pub const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the whole upstream call, body included.
pub const UPSTREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest upstream response body passed back to the agent.
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Largest request body sent upstream.
pub const MAX_UPSTREAM_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Longest `Content-Type` value accepted from an agent.
pub const MAX_CONTENT_TYPE_BYTES: usize = 255;

pub struct Outbound {
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub header_name: String,
    pub header_value: String,
    /// Agent-supplied `Content-Type`. It is sent only if it is short and has no control characters.
    pub content_type: Option<String>,
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
/// replaces any previous value and is not copied onto the response. Calls
/// time out, response bodies are capped, and only the methods in
/// [`method_allowed`] are sent.
///
/// [`HttpUpstream::new`] refuses IP-literal URLs and resolves names itself,
/// dropping loopback, private, link-local and other non-public addresses. The
/// filtered address is the one connected to, so DNS rebinding cannot swap in
/// an internal address after the check. The client ignores proxy settings
/// from the environment, because a proxy would resolve names itself and
/// bypass this filter.
pub struct HttpUpstream {
    client: reqwest::Client,
    public_only: bool,
}

impl HttpUpstream {
    pub fn new() -> Result<Self, ApiError> {
        Self::build(false)
    }

    /// Trusts any certificate and may reach loopback. Tests use this against
    /// a local server. `cargo run` uses [`HttpUpstream::new`].
    pub fn new_insecure() -> Result<Self, ApiError> {
        Self::build(true)
    }

    fn build(insecure: bool) -> Result<Self, ApiError> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .danger_accept_invalid_certs(insecure)
            .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
            .timeout(UPSTREAM_TOTAL_TIMEOUT);
        if !insecure {
            builder = builder.dns_resolver(PublicOnlyResolver);
        }
        let client = builder.build().map_err(|_| ApiError::UpstreamFailed)?;
        Ok(Self {
            client,
            public_only: !insecure,
        })
    }
}

/// Resolves with the system resolver and keeps only public addresses.
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(resolve_public(host))
    }
}

async fn resolve_public(
    host: String,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
        .await?
        .filter(|addr| is_public_ip(addr.ip()))
        .collect();
    if addrs.is_empty() {
        return Err(std::io::Error::other("upstream host has no public address").into());
    }
    let addrs: reqwest::dns::Addrs = Box::new(addrs.into_iter());
    Ok(addrs)
}

/// True when an address is globally routable. Loopback, private, link-local,
/// CGNAT, unique-local, unspecified, multicast, reserved and documentation
/// ranges are refused, as are IPv4-mapped and NAT64 forms of them.
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let octets = ip.octets();
        return is_public_v4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        // IPv4-compatible ::a.b.c.d (deprecated) and the rest of ::/96.
        || segments[..6] == [0, 0, 0, 0, 0, 0])
}

/// True when `value` may be sent as `Content-Type`.
fn content_type_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTENT_TYPE_BYTES
        && !value.chars().any(|ch| ch.is_control())
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
        // An IP literal never reaches the resolver, so it is refused here.
        if self.public_only && !matches!(url.host(), Some(url::Host::Domain(_))) {
            return Err(ApiError::UpstreamFailed);
        }
        if !method_allowed(&request.method) {
            return Err(ApiError::Forbidden);
        }
        if request.body.len() > MAX_UPSTREAM_REQUEST_BYTES {
            return Err(ApiError::PayloadTooLarge);
        }
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| ApiError::UpstreamFailed)?;
        let name = reqwest::header::HeaderName::from_bytes(request.header_name.as_bytes())
            .map_err(|_| ApiError::UpstreamFailed)?;
        let value = reqwest::header::HeaderValue::from_str(&request.header_value)
            .map_err(|_| ApiError::UpstreamFailed)?;
        let mut outgoing = self.client.request(method, url);
        if let Some(content_type) = request.content_type.as_deref() {
            if !content_type_ok(content_type) {
                return Err(ApiError::BadRequest);
            }
            let content_type = reqwest::header::HeaderValue::from_str(content_type)
                .map_err(|_| ApiError::BadRequest)?;
            outgoing = outgoing.header(reqwest::header::CONTENT_TYPE, content_type);
        }
        // The secret header goes last so an agent value cannot replace it.
        let mut response = outgoing
            .header(name, value)
            .body(request.body)
            .send()
            .await
            .map_err(|_| ApiError::UpstreamFailed)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|len| len > MAX_UPSTREAM_RESPONSE_BYTES as u64)
        {
            return Err(ApiError::UpstreamFailed);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ApiError::UpstreamFailed)?
        {
            if body.len() + chunk.len() > MAX_UPSTREAM_RESPONSE_BYTES {
                return Err(ApiError::UpstreamFailed);
            }
            body.extend_from_slice(&chunk);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn internal_addresses_are_not_public() {
        for text in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
        ] {
            assert!(!is_public_ip(ip(text)), "{text} was treated as public");
        }
    }

    #[test]
    fn public_addresses_are_public() {
        for text in [
            "1.1.1.1",
            "93.184.216.34",
            "100.63.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
        ] {
            assert!(is_public_ip(ip(text)), "{text} was treated as internal");
        }
    }

    #[test]
    fn content_type_rejects_control_characters_and_long_values() {
        assert!(content_type_ok("application/json; charset=utf-8"));
        assert!(!content_type_ok("text/plain\r\nX-Injected: 1"));
        assert!(!content_type_ok(""));
        assert!(!content_type_ok(&"a".repeat(MAX_CONTENT_TYPE_BYTES + 1)));
    }
}
