//! OIDC authorization code with PKCE.
//!
//! SAML is not implemented. A human session from this flow is an admin
//! capability. It is not a decryption key.
//!
//! Discovery must name the configured issuer exactly, and every endpoint must
//! be https unless its host is loopback. When the token endpoint returns an
//! ID token, its `iss`, `aud`, `azp`, `exp`, `nonce` and `sub` claims are
//! checked. Its IdP signature is not verified: the token comes straight from
//! the token endpoint over TLS, which OIDC Core 3.1.3.7 accepts in place of
//! the signature. Anyone who can pass as the token endpoint's TLS server can
//! therefore forge a login.
//!
//! The functions are blocking because the gateway calls them from
//! `spawn_blocking`. Each call runs one short-lived runtime on a scoped thread.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Why a login step failed. No variant carries a token, code or secret.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    #[error("could not read randomness from the OS")]
    Random,
    #[error("IdP endpoint must use https unless its host is loopback")]
    InsecureEndpoint,
    #[error("discovery document is invalid")]
    Discovery,
    #[error("discovery issuer does not match the configured issuer")]
    IssuerMismatch,
    #[error("request to the IdP failed")]
    Http,
    #[error("IdP response is invalid")]
    Response,
    #[error("ID token claims are invalid")]
    IdToken,
    #[error("IdP returned no usable subject")]
    NoSubject,
    #[error("login state does not match")]
    State,
    #[error("background runtime failed")]
    Runtime,
}

#[derive(Clone)]
pub struct OidcClient {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
}

pub struct CodeChallenge {
    pub verifier: String,
    pub challenge: String,
}

/// Allowed difference between our clock and the IdP's for `exp`.
const CLOCK_SKEW_SECS: u64 = 60;
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn code_challenge() -> Result<CodeChallenge, OidcError> {
    let verifier = random_token::<32>()?;
    let challenge = challenge_from(&verifier);
    Ok(CodeChallenge {
        verifier,
        challenge,
    })
}

pub fn challenge_from(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Nonce for the authorization request, derived from the PKCE verifier so
/// the callback can recompute it from what the caller already stores. It is
/// domain separated from the S256 challenge and does not reveal the verifier.
pub(crate) fn nonce_from(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"credentials-oidc-nonce\0");
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn random_token<const N: usize>() -> Result<String, OidcError> {
    let mut raw = [0u8; N];
    getrandom::fill(&mut raw).map_err(|_| OidcError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Authorize URL at `{issuer}/authorize`, for IdPs without discovery.
pub fn authorize_url(client: &OidcClient, challenge: &str, state: &str) -> String {
    let endpoint = format!("{}/authorize", client.issuer.trim_end_matches('/'));
    authorization_request(&endpoint, client, challenge, state, None)
}

/// Exchange a code at `token_url` and return the access token.
pub fn exchange_code(
    token_url: &str,
    client: &OidcClient,
    code: &str,
    verifier: &str,
    client_secret: Option<&str>,
) -> Result<Zeroizing<String>, OidcError> {
    let tokens = block_on(async {
        let http = http_client()?;
        exchange(&http, token_url, client, code, verifier, client_secret).await
    })?;
    Ok(tokens.access_token)
}

struct Tokens {
    access_token: Zeroizing<String>,
    id_token: Option<Zeroizing<String>>,
}

async fn exchange(
    http: &reqwest::Client,
    token_url: &str,
    client: &OidcClient,
    code: &str,
    verifier: &str,
    client_secret: Option<&str>,
) -> Result<Tokens, OidcError> {
    check_endpoint(token_url)?;
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", client.redirect_uri.as_str()),
        ("client_id", client.client_id.as_str()),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client_secret {
        pairs.push(("client_secret", secret));
    }
    let body = form_encode(&pairs);
    let value = read_json(
        http.post(token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(String::clone(&body)),
    )
    .await?;
    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(|token| Zeroizing::new(token.to_owned()))
        .ok_or(OidcError::Response)?;
    let id_token = match value.get("id_token") {
        None | Some(Value::Null) => None,
        Some(Value::String(token)) => Some(Zeroizing::new(token.clone())),
        Some(_) => return Err(OidcError::Response),
    };
    Ok(Tokens {
        access_token,
        id_token,
    })
}

/// Run `future` on a current-thread runtime in a scoped thread, so callers
/// inside or outside a runtime can block on it.
fn block_on<T: Send>(
    future: impl std::future::Future<Output = Result<T, OidcError>> + Send,
) -> Result<T, OidcError> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| OidcError::Runtime)?
                    .block_on(future)
            })
            .join()
            .unwrap_or(Err(OidcError::Runtime))
    })
}

fn http_client() -> Result<reqwest::Client, OidcError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| OidcError::Http)
}

async fn read_json(request: reqwest::RequestBuilder) -> Result<Value, OidcError> {
    request
        .send()
        .await
        .map_err(|_| OidcError::Http)?
        .error_for_status()
        .map_err(|_| OidcError::Http)?
        .json()
        .await
        .map_err(|_| OidcError::Response)
}

/// Require https, or http to a loopback host.
fn check_endpoint(url: &str) -> Result<(), OidcError> {
    if crate::net::is_secure_url(url) {
        Ok(())
    } else {
        Err(OidcError::InsecureEndpoint)
    }
}

fn now_unix() -> Result<u64, OidcError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| OidcError::IdToken)
}

#[derive(Debug)]
pub struct HumanLogin {
    pub subject: String,
}

pub struct BrowserLogin {
    pub url: String,
    pub state: String,
    pub verifier: String,
}

/// Build the authorize redirect. The caller stores `verifier` until the
/// callback. The request also carries a nonce derived from `verifier`.
pub fn start_browser_login(client: &OidcClient) -> Result<BrowserLogin, OidcError> {
    let pkce = code_challenge()?;
    let state = random_token::<16>()?;
    let nonce = nonce_from(&pkce.verifier);
    let endpoints = block_on(async {
        let http = http_client()?;
        discover(&http, &client.issuer).await
    })?;
    let url = authorization_request(
        &endpoints.authorize,
        client,
        &pkce.challenge,
        &state,
        Some(&nonce),
    );
    Ok(BrowserLogin {
        url,
        state,
        verifier: pkce.verifier,
    })
}

/// Exchange the callback code. The access token is dropped after userinfo.
///
/// The subject is the userinfo `email` when `email_verified` is true, and
/// `sub` otherwise. An empty subject is an error.
pub fn finish_browser_login(
    client: &OidcClient,
    client_secret: Option<&str>,
    code: &str,
    verifier: &str,
) -> Result<HumanLogin, OidcError> {
    let now = now_unix()?;
    let subject = block_on(finish(client, client_secret, code, verifier, now))?;
    Ok(HumanLogin { subject })
}

async fn finish(
    client: &OidcClient,
    client_secret: Option<&str>,
    code: &str,
    verifier: &str,
    now_unix: u64,
) -> Result<String, OidcError> {
    let http = http_client()?;
    let endpoints = discover(&http, &client.issuer).await?;
    let tokens = exchange(
        &http,
        &endpoints.token,
        client,
        code,
        verifier,
        client_secret,
    )
    .await?;
    let id_subject = match &tokens.id_token {
        Some(token) => Some(check_id_token(
            token,
            client,
            &nonce_from(verifier),
            now_unix,
        )?),
        None => None,
    };
    let userinfo = read_json(
        http.get(&endpoints.userinfo)
            .bearer_auth(tokens.access_token.as_str()),
    )
    .await?;
    drop(tokens);
    // OIDC Core 5.3.2: userinfo `sub` must match the ID token `sub`.
    if let Some(id_subject) = id_subject {
        if userinfo.get("sub").and_then(Value::as_str) != Some(id_subject.as_str()) {
            return Err(OidcError::IdToken);
        }
    }
    subject_from(&userinfo)
}

/// Finish an authorization-code login by posting the IdP password form.
/// Test helper only: it scrapes a form and does not belong in a product path.
#[cfg(any(test, feature = "test-util"))]
pub fn login_with_password(
    client: &OidcClient,
    client_secret: Option<&str>,
    username: &str,
    password: &str,
) -> Result<HumanLogin, OidcError> {
    let started = start_browser_login(client)?;
    let (code, returned_state) = block_on(drive_login(
        &started.url,
        &client.redirect_uri,
        username,
        password,
    ))?;
    if returned_state != started.state {
        return Err(OidcError::State);
    }
    finish_browser_login(client, client_secret, &code, &started.verifier)
}

#[derive(Debug)]
pub(crate) struct Endpoints {
    pub(crate) authorize: String,
    pub(crate) token: String,
    pub(crate) userinfo: String,
}

async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Endpoints, OidcError> {
    check_endpoint(issuer)?;
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let value = read_json(http.get(url)).await?;
    parse_discovery(&value, issuer)
}

/// Check a discovery document against the configured issuer.
pub(crate) fn parse_discovery(value: &Value, issuer: &str) -> Result<Endpoints, OidcError> {
    if text(value, "issuer")? != issuer {
        return Err(OidcError::IssuerMismatch);
    }
    let endpoints = Endpoints {
        authorize: text(value, "authorization_endpoint")?,
        token: text(value, "token_endpoint")?,
        userinfo: text(value, "userinfo_endpoint")?,
    };
    check_endpoint(&endpoints.authorize)?;
    check_endpoint(&endpoints.token)?;
    check_endpoint(&endpoints.userinfo)?;
    Ok(endpoints)
}

fn text(value: &Value, key: &str) -> Result<String, OidcError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(OidcError::Discovery)
}

pub(crate) fn authorization_request(
    endpoint: &str,
    client: &OidcClient,
    challenge: &str,
    state: &str,
    nonce: Option<&str>,
) -> String {
    let mut pairs = vec![
        ("response_type", "code"),
        ("client_id", client.client_id.as_str()),
        ("redirect_uri", client.redirect_uri.as_str()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("scope", "openid email"),
    ];
    if let Some(nonce) = nonce {
        pairs.push(("nonce", nonce));
    }
    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{separator}{}", form_encode(&pairs).as_str())
}

/// Check ID token claims and return its `sub`. The signature is not checked.
pub(crate) fn check_id_token(
    token: &str,
    client: &OidcClient,
    nonce: &str,
    now_unix: u64,
) -> Result<String, OidcError> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(OidcError::IdToken);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| OidcError::IdToken)?;
    let claims: Value = serde_json::from_slice(&bytes).map_err(|_| OidcError::IdToken)?;
    let client_id = client.client_id.as_str();
    if claims.get("iss").and_then(Value::as_str) != Some(client.issuer.as_str()) {
        return Err(OidcError::IdToken);
    }
    let azp = claims.get("azp").map(Value::as_str);
    let audience_ok = match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|aud| aud.as_str() == Some(client_id))
                && (list.len() == 1 || azp.is_some())
        }
        _ => false,
    };
    if !audience_ok {
        return Err(OidcError::IdToken);
    }
    if let Some(azp) = azp {
        if azp != Some(client_id) {
            return Err(OidcError::IdToken);
        }
    }
    let exp = claims
        .get("exp")
        .and_then(|exp| {
            exp.as_u64()
                .or_else(|| exp.as_f64().map(|secs| secs as u64))
        })
        .ok_or(OidcError::IdToken)?;
    if exp.saturating_add(CLOCK_SKEW_SECS) <= now_unix {
        return Err(OidcError::IdToken);
    }
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err(OidcError::IdToken);
    }
    match claims.get("sub").and_then(Value::as_str) {
        Some(sub) if !sub.is_empty() => Ok(sub.to_owned()),
        _ => Err(OidcError::IdToken),
    }
}

/// Pick the login subject from userinfo claims.
pub(crate) fn subject_from(userinfo: &Value) -> Result<String, OidcError> {
    let verified = match userinfo.get("email_verified") {
        Some(Value::Bool(verified)) => *verified,
        Some(Value::String(text)) => text == "true",
        _ => false,
    };
    let email = userinfo
        .get("email")
        .and_then(Value::as_str)
        .filter(|email| !email.trim().is_empty());
    let subject = match email {
        Some(email) if verified => email,
        _ => userinfo.get("sub").and_then(Value::as_str).unwrap_or(""),
    };
    if subject.trim().is_empty() {
        return Err(OidcError::NoSubject);
    }
    Ok(subject.to_owned())
}

#[cfg(any(test, feature = "test-util"))]
async fn drive_login(
    start: &str,
    redirect_uri: &str,
    username: &str,
    password: &str,
) -> Result<(String, String), OidcError> {
    let http = http_client()?;
    let mut url = start.to_owned();
    for _ in 0..6 {
        let response = http.get(&url).send().await.map_err(|_| OidcError::Http)?;
        if response.status().is_redirection() {
            url = location(&url, &response)?;
            if let Some(pair) = callback_code(&url, redirect_uri) {
                return Ok(pair);
            }
            continue;
        }
        if !response.status().is_success() {
            return Err(OidcError::Http);
        }
        let body = form_encode(&[("login", username), ("password", password)]);
        let posted = http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(String::clone(&body))
            .send()
            .await
            .map_err(|_| OidcError::Http)?;
        if !posted.status().is_redirection() {
            return Err(OidcError::Http);
        }
        url = location(&url, &posted)?;
        if let Some(pair) = callback_code(&url, redirect_uri) {
            return Ok(pair);
        }
    }
    Err(OidcError::Http)
}

#[cfg(any(test, feature = "test-util"))]
fn location(current: &str, response: &reqwest::Response) -> Result<String, OidcError> {
    let header = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .ok_or(OidcError::Response)?;
    let base = reqwest::Url::parse(current).map_err(|_| OidcError::Response)?;
    base.join(header)
        .map(|url| url.to_string())
        .map_err(|_| OidcError::Response)
}

#[cfg(any(test, feature = "test-util"))]
fn callback_code(url: &str, redirect_uri: &str) -> Option<(String, String)> {
    if !url.starts_with(redirect_uri) {
        return None;
    }
    let parsed = reqwest::Url::parse(url).ok()?;
    let mut code = None;
    let mut state = None;
    for (name, value) in parsed.query_pairs() {
        match name.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    Some((code?, state?))
}

/// Map an IdP group to a workspace role. `inject` is not a role here.
pub fn role_for_group(group: &str) -> Option<&'static str> {
    match group {
        "credentials-admin" => Some("admin"),
        "credentials-audit" => Some("audit"),
        _ => None,
    }
}

/// Encode pairs as `application/x-www-form-urlencoded`. Every byte outside
/// the RFC 3986 unreserved set is percent-encoded, so `&`, `=`, `+` and
/// spaces in a value cannot change the parameters. The result may hold a
/// client secret, so it is zeroized on drop.
pub(crate) fn form_encode(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let capacity = pairs
        .iter()
        .map(|(name, value)| 3 * (name.len() + value.len()) + 2)
        .sum();
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        crate::net::push_encoded(&mut out, name);
        out.push('=');
        crate::net::push_encoded(&mut out, value);
    }
    out
}
