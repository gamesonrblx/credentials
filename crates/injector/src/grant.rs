//! Signed grant verification.
//!
//! The control plane signs `b"credentials.grant.v1\n" || grant` with Ed25519.
//! Nothing in the authorisation object is read before that signature verifies.

use credentials_crypto::{open_e2e, E2eSealed, VersionIds};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::json::{
    b64_decode, b64_field, is_sha256_hex, nonce_field, sha256_hex, str_field, u64_field, uuid_field,
};
use crate::InjectorError;

/// Domain-separation prefix for the grant signature.
pub const GRANT_SIGNING_PREFIX: &[u8] = b"credentials.grant.v1\n";
/// How far `iat` may sit in the future.
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;
/// Longest `exp - iat` a grant may claim.
pub const MAX_GRANT_LIFETIME_SECS: u64 = 300;

const MAX_HEADER_NAME_LEN: usize = 128;
const MAX_ENV_NAME_LEN: usize = 256;

/// Header names the injector never sets from a grant.
const FORBIDDEN_HEADERS: &[&str] = &[
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

/// Methods a proxy grant may name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// Exact, case-sensitive match on the six allowed methods.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// The one upstream request a proxy grant allows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPolicy {
    pub method: HttpMethod,
    /// A bare `https` URL whose host equals `host`.
    pub url: Url,
    pub host: String,
    /// Lowercase hex SHA-256 of the request body.
    pub body_sha256: String,
    pub content_type: Option<String>,
    pub header_name: String,
    /// Contains `{value}` exactly once.
    pub header_format: String,
}

/// The delivery a grant authorises.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantDelivery {
    Proxy(ProxyPolicy),
    Header {
        header_name: String,
        header_format: String,
    },
    Env {
        env_name: String,
    },
}

/// A grant whose signature, ids, lifetime, ciphertext hash, and delivery
/// fields were checked. Only [`verify_grant`] builds one.
#[derive(Clone, Debug)]
pub struct VerifiedGrant {
    pub iss: String,
    pub kid: String,
    pub ids: VersionIds,
    pub workspace_key_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub secret_name: String,
    pub iat: u64,
    pub exp: u64,
    pub delivery: GrantDelivery,
    sealed: E2eSealed,
}

impl VerifiedGrant {
    /// Decrypt the payload. Callers outside this crate use [`crate::deliver`].
    pub(crate) fn open(
        &self,
        decapsulation_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, InjectorError> {
        open_e2e(decapsulation_key, &self.sealed, self.ids).map_err(|_| InjectorError::Open)
    }
}

/// Accept either the grant object itself or the HTTP envelope
/// `{"upstream_status":200,"body":"<base64 grant>"}` that `POST /v1/inject`
/// returns, and give back the grant bytes.
pub fn grant_from_inject_response(bytes: &[u8]) -> Result<Vec<u8>, InjectorError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| InjectorError::Grant)?;
    if value.get("wrap_mode").is_some() {
        return Ok(bytes.to_vec());
    }
    b64_decode(str_field(&value, "body")?)
}

/// Verify a signed grant against the control-plane Ed25519 key.
///
/// The signature is checked with strict verification before any field of the
/// authorisation object is trusted. An unsigned legacy grant is refused.
pub fn verify_grant(
    control_plane_key: &[u8; 32],
    grant_json: &[u8],
    now_unix: u64,
) -> Result<VerifiedGrant, InjectorError> {
    let outer: Value = serde_json::from_slice(grant_json).map_err(|_| InjectorError::Grant)?;
    if !outer.is_object() || str_field(&outer, "wrap_mode")? != "e2e" {
        return Err(InjectorError::Grant);
    }

    let (Some(grant_b64), Some(signature_b64)) = (
        outer.get("grant").and_then(|v| v.as_str()),
        outer.get("grant_signature").and_then(|v| v.as_str()),
    ) else {
        return Err(InjectorError::Unsigned);
    };
    let grant_kid = str_field(&outer, "grant_kid")?;
    let grant_bytes = b64_decode(grant_b64)?;
    let signature: [u8; 64] = b64_decode(signature_b64)
        .map_err(|_| InjectorError::Signature)?
        .try_into()
        .map_err(|_| InjectorError::Signature)?;
    let key = VerifyingKey::from_bytes(control_plane_key).map_err(|_| InjectorError::Signature)?;
    let mut message = Vec::with_capacity(GRANT_SIGNING_PREFIX.len() + grant_bytes.len());
    message.extend_from_slice(GRANT_SIGNING_PREFIX);
    message.extend_from_slice(&grant_bytes);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| InjectorError::Signature)?;

    // The authorisation object is trusted from here on.
    let auth: Value = serde_json::from_slice(&grant_bytes).map_err(|_| InjectorError::Grant)?;
    if !auth.is_object() || u64_field(&auth, "v")? != 1 {
        return Err(InjectorError::Grant);
    }
    let iss = str_field(&auth, "iss")?;
    let kid = str_field(&auth, "kid")?;
    if iss.is_empty() || kid != grant_kid {
        return Err(InjectorError::Policy);
    }

    let ids = VersionIds {
        workspace_id: uuid_field(&outer, "workspace_id")?,
        secret_id: uuid_field(&outer, "secret_id")?,
        version_id: uuid_field(&outer, "version_id")?,
    };
    let workspace_key_id = uuid_field(&outer, "workspace_key_id")?;
    if uuid_field(&auth, "workspace_id")? != ids.workspace_id
        || uuid_field(&auth, "secret_id")? != ids.secret_id
        || uuid_field(&auth, "version_id")? != ids.version_id
        || uuid_field(&auth, "workspace_key_id")? != workspace_key_id
    {
        return Err(InjectorError::Policy);
    }
    let agent_id = match auth.get("agent_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(Uuid::parse_str(text).map_err(|_| InjectorError::Grant)?),
        Some(_) => return Err(InjectorError::Grant),
    };
    let secret_name = str_field(&auth, "secret_name")?;

    let iat = u64_field(&auth, "iat")?;
    let exp = u64_field(&auth, "exp")?;
    let lifetime = exp.checked_sub(iat).ok_or(InjectorError::Expired)?;
    if lifetime == 0
        || lifetime > MAX_GRANT_LIFETIME_SECS
        || iat > now_unix.saturating_add(MAX_CLOCK_SKEW_SECS)
        || now_unix >= exp
    {
        return Err(InjectorError::Expired);
    }

    let payload_ciphertext = b64_field(&outer, "payload_ciphertext")?;
    let expected_hash = str_field(&auth, "ciphertext_sha256")?;
    if !is_sha256_hex(expected_hash) || sha256_hex(&payload_ciphertext) != expected_hash {
        return Err(InjectorError::Policy);
    }
    let plaintext_len =
        usize::try_from(u64_field(&outer, "plaintext_len")?).map_err(|_| InjectorError::Grant)?;
    let sealed = E2eSealed {
        workspace_key_id,
        payload_nonce: nonce_field(&outer, "payload_nonce")?,
        payload_ciphertext,
        dek_wrap_nonce: nonce_field(&outer, "dek_wrap_nonce")?,
        dek_wrapped: b64_field(&outer, "dek_wrapped")?,
        encapsulation: b64_field(&outer, "e2e_encapsulation")?,
        plaintext_len,
    };

    let delivery = match str_field(&auth, "delivery")? {
        "proxy" => GrantDelivery::Proxy(proxy_policy(&auth)?),
        "header" => GrantDelivery::Header {
            header_name: header_name(&auth)?,
            header_format: header_format(&auth)?,
        },
        "env" => GrantDelivery::Env {
            env_name: env_name(&auth)?,
        },
        _ => return Err(InjectorError::Policy),
    };

    Ok(VerifiedGrant {
        iss: iss.to_owned(),
        kid: kid.to_owned(),
        ids,
        workspace_key_id,
        agent_id,
        secret_name: secret_name.to_owned(),
        iat,
        exp,
        delivery,
        sealed,
    })
}

fn proxy_policy(auth: &Value) -> Result<ProxyPolicy, InjectorError> {
    let method = HttpMethod::parse(str_field(auth, "method")?).ok_or(InjectorError::Method)?;
    let host = str_field(auth, "host")?;
    if host.is_empty() {
        return Err(InjectorError::Url);
    }
    let url = proxy_url(str_field(auth, "url")?, host)?;
    let body_sha256 = str_field(auth, "body_sha256")?;
    if !is_sha256_hex(body_sha256) {
        return Err(InjectorError::Policy);
    }
    let content_type = match auth.get("content_type") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if !text.is_empty() && safe_header_text(text) => {
            Some(text.clone())
        }
        Some(_) => return Err(InjectorError::Policy),
    };
    Ok(ProxyPolicy {
        method,
        url,
        host: host.to_owned(),
        body_sha256: body_sha256.to_owned(),
        content_type,
        header_name: header_name(auth)?,
        header_format: header_format(auth)?,
    })
}

/// Parse a proxy URL: `https`, no userinfo, no explicit port, host equal to
/// `host` ignoring ASCII case. The raw authority is checked too, because the
/// URL parser drops a written `:443`.
fn proxy_url(raw: &str, host: &str) -> Result<Url, InjectorError> {
    let scheme_ok = raw
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
    if !scheme_ok {
        return Err(InjectorError::Url);
    }
    let rest = raw.get(8..).ok_or(InjectorError::Url)?;
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(InjectorError::Url);
    }
    let has_port = if authority.starts_with('[') {
        !authority.ends_with(']')
    } else {
        authority.contains(':')
    };
    if has_port {
        return Err(InjectorError::Url);
    }
    let url = Url::parse(raw).map_err(|_| InjectorError::Url)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(InjectorError::Url);
    }
    match url.host_str() {
        Some(parsed) if parsed.eq_ignore_ascii_case(host) => Ok(url),
        _ => Err(InjectorError::Url),
    }
}

fn header_name(auth: &Value) -> Result<String, InjectorError> {
    let name = str_field(auth, "header_name")?;
    let token = !name.is_empty()
        && name.len() <= MAX_HEADER_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if !token
        || FORBIDDEN_HEADERS
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(name))
    {
        return Err(InjectorError::HeaderValue);
    }
    Ok(name.to_owned())
}

fn header_format(auth: &Value) -> Result<String, InjectorError> {
    let format = str_field(auth, "header_format")?;
    if format.matches("{value}").count() != 1 || !safe_header_text(format) {
        return Err(InjectorError::HeaderValue);
    }
    Ok(format.to_owned())
}

fn env_name(auth: &Value) -> Result<String, InjectorError> {
    let name = str_field(auth, "env_name")?;
    if !valid_env_name(name) {
        return Err(InjectorError::Policy);
    }
    Ok(name.to_owned())
}

/// `[A-Za-z_][A-Za-z0-9_]*`, at most 256 bytes.
pub(crate) fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= MAX_ENV_NAME_LEN
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// No CR, LF, NUL, or other control character except tab.
pub(crate) fn safe_header_text(text: &str) -> bool {
    text.chars()
        .all(|c| c == '\t' || (c >= ' ' && c != '\u{7f}'))
}
