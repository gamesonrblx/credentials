//! Scope matching and delivery-policy checks.
//!
//! `*` matches one path segment. `secret:admin:*` is the only pattern that
//! covers every name, and agent sessions are not allowed to hold it.

use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryPolicy {
    pub header_name: Option<String>,
    pub header_format: Option<String>,
    pub env_name: Option<String>,
    pub hosts: Vec<String>,
    pub allow_proxy: bool,
    pub allow_header: bool,
    pub allow_env: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    Proxy,
    Header,
    Env,
}

impl Delivery {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proxy" => Some(Self::Proxy),
            "header" => Some(Self::Header),
            "env" => Some(Self::Env),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Header => "header",
            Self::Env => "env",
        }
    }
}

pub fn validate_policy(policy: &DeliveryPolicy) -> Result<(), &'static str> {
    if !(policy.allow_proxy || policy.allow_header || policy.allow_env) {
        return Err("at least one delivery mode is required");
    }
    if policy.allow_proxy || policy.allow_header {
        if policy.hosts.is_empty() {
            return Err("proxy and header delivery require a host list");
        }
        let format = policy.header_format.as_deref().unwrap_or("");
        if format.matches("{value}").count() != 1 || format.matches('{').count() != 1 {
            return Err("header_format must contain {value} once");
        }
        if format.chars().any(|c| c.is_control() && c != '\t') {
            return Err("header_format must not contain control characters");
        }
        let name = policy.header_name.as_deref().unwrap_or("");
        if name.is_empty() {
            return Err("header_name is required");
        }
        if !header_name_allowed(name) {
            return Err("header_name must be an HTTP token and not a framing header");
        }
    }
    if policy.allow_env {
        let name = policy.env_name.as_deref().unwrap_or("");
        if name.is_empty() {
            return Err("env delivery requires env_name");
        }
        if !env_name_allowed(name) {
            return Err("env_name must match [A-Za-z_][A-Za-z0-9_]*");
        }
    }
    for host in &policy.hosts {
        if host.is_empty()
            || host.contains(':')
            || host.contains('/')
            || host.chars().any(|c| c.is_whitespace())
        {
            return Err("hosts are bare hostnames");
        }
        if !public_hostname(host) {
            return Err("hosts must be public DNS names, not IP addresses or internal names");
        }
    }
    Ok(())
}

/// Headers that frame or route the request. A secret must not replace them.
const FRAMING_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

/// True for an RFC 7230 token of at most 128 bytes that is not a framing
/// header. The injector applies the same rule to a signed grant, so a policy
/// that passes here yields a grant the injector accepts.
pub fn header_name_allowed(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    let token = name.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    });
    token
        && !FRAMING_HEADERS
            .iter()
            .any(|framing| name.eq_ignore_ascii_case(framing))
}

/// True for a POSIX environment variable name.
pub fn env_name_allowed(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Suffixes that name hosts on a private network.
const INTERNAL_SUFFIXES: &[&str] = &[".localhost", ".local", ".internal", ".lan", ".home.arpa"];

/// True for a multi-label DNS name that is not an IP literal, `localhost`,
/// or under an internal-only suffix. The upstream resolver still refuses
/// names that resolve to internal addresses.
fn public_hostname(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // URL parsing also reads forms like `127.1` or `0x7f.1` as IPv4.
    let is_domain = match Url::parse(&format!("https://{host}/")) {
        Ok(url) => matches!(url.host(), Some(url::Host::Domain(_))),
        Err(_) => false,
    };
    if !is_domain {
        return false;
    }
    if host == "localhost" || !host.contains('.') {
        return false;
    }
    !INTERNAL_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(suffix))
}

/// HTTP methods an agent may send upstream. TRACE, CONNECT and others are refused.
pub fn method_allowed(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Agent sessions may only carry `secret:inject:...` scopes.
pub fn scope_allowed_on_agent(scope: &str) -> bool {
    let Some(path) = scope.strip_prefix("secret:inject:") else {
        return false;
    };
    !path.is_empty() && !path.contains("**") && valid_scope_path(path)
}

pub fn scope_allows(scopes: &[String], needed: &str, name: &str) -> bool {
    let name_segs: Vec<&str> = name.split('/').filter(|s| !s.is_empty()).collect();
    if name_segs.is_empty() {
        return false;
    }
    scopes.iter().any(|scope| {
        let Some(rest) = scope.strip_prefix("secret:") else {
            return false;
        };
        let Some((action, path)) = rest.split_once(':') else {
            return false;
        };
        if action != needed && action != "admin" {
            return false;
        }
        if action == "admin" && path == "*" {
            return true;
        }
        path_matches(path, &name_segs)
    })
}

pub fn delivery_allowed(policy: &DeliveryPolicy, delivery: Delivery) -> bool {
    match delivery {
        Delivery::Proxy => policy.allow_proxy,
        Delivery::Header => policy.allow_header,
        Delivery::Env => policy.allow_env,
    }
}

pub fn https_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if parsed.port().is_some() {
        return None;
    }
    Some(host)
}

pub fn host_allowed(hosts: &[String], host: &str) -> bool {
    hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
}

pub fn format_header(format: &str, value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?;
    let (head, tail) = format.split_once("{value}")?;
    if tail.contains("{value}") {
        return None;
    }
    Some(format!("{head}{value}{tail}"))
}

fn valid_scope_path(path: &str) -> bool {
    path.split('/').all(|seg| seg == "*" || valid_segment(seg))
}

fn valid_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

fn path_matches(pattern: &str, name: &[&str]) -> bool {
    let parts: Vec<&str> = pattern.split('/').collect();
    if parts.len() != name.len() {
        return false;
    }
    parts
        .iter()
        .zip(name.iter())
        .all(|(pattern, name)| *pattern == "*" || *pattern == *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_matches_one_segment_and_admin_star_matches_all() {
        let scopes = vec!["secret:inject:prod/openai/*".to_owned()];
        assert!(scope_allows(&scopes, "inject", "prod/openai/api_key"));
        assert!(!scope_allows(&scopes, "inject", "prod/other/api_key"));
        assert!(!scope_allows(&scopes, "write", "prod/openai/api_key"));
        let admin = vec!["secret:admin:*".to_owned()];
        assert!(scope_allows(&admin, "inject", "a/b/c"));
        assert!(!scope_allowed_on_agent("secret:admin:*"));
        assert!(scope_allowed_on_agent("secret:inject:prod/openai/*"));
    }

    fn with_hosts(hosts: &[&str]) -> DeliveryPolicy {
        DeliveryPolicy {
            header_name: Some("Authorization".into()),
            header_format: Some("Bearer {value}".into()),
            env_name: None,
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            allow_proxy: true,
            allow_header: false,
            allow_env: false,
        }
    }

    #[test]
    fn header_and_env_names_match_what_the_injector_accepts() {
        for name in ["Authorization", "x-api-key", "X_Custom.Header~1"] {
            let mut policy = with_hosts(&["api.openai.com"]);
            policy.header_name = Some(name.into());
            assert!(validate_policy(&policy).is_ok(), "{name}");
        }
        let long = "a".repeat(129);
        for name in [
            "Host",
            "content-length",
            "Content-Type",
            "Transfer-Encoding",
            "Connection",
            "bad name",
            "bad:name",
            "bad\r\nname",
            long.as_str(),
        ] {
            let mut policy = with_hosts(&["api.openai.com"]);
            policy.header_name = Some(name.into());
            assert!(validate_policy(&policy).is_err(), "{name:?}");
        }
        let mut policy = with_hosts(&["api.openai.com"]);
        policy.header_format = Some("Bearer {value}\r\nX-Evil: 1".into());
        assert!(validate_policy(&policy).is_err());

        for (name, ok) in [
            ("OPENAI_API_KEY", true),
            ("_private", true),
            ("1ST", false),
            ("HAS-DASH", false),
            ("HAS SPACE", false),
            ("A=B", false),
        ] {
            let mut policy = with_hosts(&["api.openai.com"]);
            policy.allow_env = true;
            policy.env_name = Some(name.into());
            assert_eq!(validate_policy(&policy).is_ok(), ok, "{name}");
        }
    }

    #[test]
    fn internal_hosts_are_rejected() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "127.1",
            "0x7f000001",
            "localhost",
            "LOCALHOST.",
            "metadata",
            "printer.local",
            "db.internal",
            "nas.lan",
            "router.home.arpa",
            "app.localhost",
            "::1",
            "[::1]",
        ] {
            assert!(
                validate_policy(&with_hosts(&[host])).is_err(),
                "{host} was accepted"
            );
        }
    }

    #[test]
    fn public_hosts_are_accepted() {
        for host in ["api.openai.com", "api.example.com", "Api.Stripe.com"] {
            assert!(
                validate_policy(&with_hosts(&[host])).is_ok(),
                "{host} was rejected"
            );
        }
    }

    #[test]
    fn only_listed_methods_are_allowed() {
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(method_allowed(method));
        }
        for method in ["TRACE", "CONNECT", "OPTIONS", "get", "PROPFIND", ""] {
            assert!(!method_allowed(method));
        }
    }
}
