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
        if policy.header_name.as_deref().unwrap_or("").is_empty() {
            return Err("header_name is required");
        }
    }
    if policy.allow_env && policy.env_name.as_deref().unwrap_or("").is_empty() {
        return Err("env delivery requires env_name");
    }
    for host in &policy.hosts {
        if host.is_empty()
            || host.contains(':')
            || host.contains('/')
            || host.chars().any(|c| c.is_whitespace())
        {
            return Err("hosts are bare hostnames");
        }
    }
    Ok(())
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
}
