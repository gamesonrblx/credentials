//! Small URL and HTTP helpers shared by the adapters.

/// Timeout for every adapter HTTP request.
pub(crate) const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A client with [`HTTP_TIMEOUT`] that does not follow redirects, so a
/// bearer token is never replayed to another host or over plain http.
pub(crate) fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
}

/// True for an https URL with a host, or an http URL whose host is loopback.
pub(crate) fn is_secure_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        "http" => match parsed.host_str() {
            Some("localhost") => true,
            Some(host) => host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false),
            None => false,
        },
        _ => false,
    }
}

/// Percent-encode every byte outside the RFC 3986 unreserved set.
pub(crate) fn push_encoded(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                out.push('%');
                out.push(HEX[usize::from(byte >> 4)] as char);
                out.push(HEX[usize::from(byte & 0x0f)] as char);
            }
        }
    }
}

/// One encoded URL path segment or query value. `/`, `?`, `&` and `#`
/// are encoded, so a value cannot add segments or parameters.
pub(crate) fn component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    push_encoded(&mut out, value);
    out
}

/// A multi-segment path such as a Vault KV path or an S3 key. Each segment
/// is encoded; empty, `.` and `..` segments are refused.
pub(crate) fn path(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    for (index, segment) in value.split('/').enumerate() {
        if segment.is_empty() || segment == "." || segment == ".." {
            return None;
        }
        if index > 0 {
            out.push('/');
        }
        push_encoded(&mut out, segment);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_http_is_secure() {
        assert!(is_secure_url("https://vault.example"));
        assert!(is_secure_url("http://127.0.0.1:8200"));
        assert!(is_secure_url("http://[::1]:8200"));
        assert!(is_secure_url("http://localhost:8080"));
        assert!(!is_secure_url("http://vault.example"));
        assert!(!is_secure_url("http://10.0.0.5"));
        assert!(!is_secure_url("ftp://127.0.0.1"));
        assert!(!is_secure_url("not a url"));
    }

    #[test]
    fn components_and_paths_cannot_escape() {
        assert_eq!(component("a/b?c=d&e#f"), "a%2Fb%3Fc%3Dd%26e%23f");
        assert_eq!(path("team/app key").as_deref(), Some("team/app%20key"));
        assert_eq!(path("a/../b"), None);
        assert_eq!(path("/a"), None);
        assert_eq!(path("a//b"), None);
    }
}
