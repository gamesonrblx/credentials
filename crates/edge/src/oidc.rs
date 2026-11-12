//! OIDC authorization code with PKCE.
//!
//! SAML is not implemented. A human session from this flow is an admin
//! capability. It is not a decryption key.

use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct OidcError;

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

pub fn code_challenge() -> CodeChallenge {
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("os random");
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    CodeChallenge {
        verifier,
        challenge,
    }
}

pub fn challenge_from(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

pub fn authorize_url(client: &OidcClient, challenge: &str, state: &str) -> String {
    format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scope=openid%20email",
        client.issuer.trim_end_matches('/'),
        client.client_id,
        urlencoding(&client.redirect_uri),
        challenge,
        state
    )
}

pub fn exchange_code(
    token_url: &str,
    client: &OidcClient,
    code: &str,
    verifier: &str,
    client_secret: Option<&str>,
) -> Result<String, OidcError> {
    let mut body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier={verifier}",
        urlencoding(&client.redirect_uri),
        client.client_id
    );
    if let Some(secret) = client_secret {
        body.push_str("&client_secret=");
        body.push_str(&urlencoding(secret));
    }
    let token_url = token_url.to_owned();
    let access = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("oidc runtime")
                    .block_on(async move {
                        let value: serde_json::Value = reqwest::Client::new()
                            .post(token_url)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .body(body)
                            .send()
                            .await
                            .map_err(|_| OidcError)?
                            .error_for_status()
                            .map_err(|_| OidcError)?
                            .json()
                            .await
                            .map_err(|_| OidcError)?;
                        value
                            .get("access_token")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                            .ok_or(OidcError)
                    })
            })
            .join()
            .expect("oidc thread")
    })?;
    Ok(access)
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

/// Build the authorize redirect. The caller stores `verifier` until the callback.
pub fn start_browser_login(client: &OidcClient) -> Result<BrowserLogin, OidcError> {
    let pkce = code_challenge();
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("os random");
    let state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let endpoints = discover_sync(&client.issuer)?;
    let url = authorization_request(&endpoints.authorize, client, &pkce.challenge, &state);
    Ok(BrowserLogin {
        url,
        state,
        verifier: pkce.verifier,
    })
}

/// Exchange the callback code. The access token is dropped after userinfo.
pub fn finish_browser_login(
    client: &OidcClient,
    client_secret: Option<&str>,
    code: &str,
    verifier: &str,
) -> Result<HumanLogin, OidcError> {
    let endpoints = discover_sync(&client.issuer)?;
    let token = exchange_code(&endpoints.token, client, code, verifier, client_secret)?;
    let userinfo = endpoints.userinfo;
    let subject = std::thread::scope(|scope| {
        let token = token.clone();
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("oidc runtime")
                    .block_on(read_subject(&userinfo, &token))
            })
            .join()
            .expect("oidc thread")
    })?;
    Ok(HumanLogin { subject })
}

fn discover_sync(issuer: &str) -> Result<Endpoints, OidcError> {
    let issuer = issuer.trim_end_matches('/').to_owned();
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("oidc runtime")
                    .block_on(discover(&issuer))
            })
            .join()
            .expect("oidc thread")
    })
}

/// Finish an authorization-code login by posting the IdP password form.
/// The returned subject is the userinfo email. The access token is not returned.
pub fn login_with_password(
    client: &OidcClient,
    client_secret: Option<&str>,
    username: &str,
    password: &str,
) -> Result<HumanLogin, OidcError> {
    let started = start_browser_login(client)?;
    let state = started.state.clone();
    let verifier = started.verifier.clone();
    let redirect_uri = client.redirect_uri.clone();
    let username = username.to_owned();
    let password = password.to_owned();
    let (code, returned_state) = std::thread::scope(|scope| {
        scope
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("oidc runtime")
                    .block_on(drive_login(started.url, redirect_uri, username, password))
            })
            .join()
            .expect("oidc thread")
    })?;
    if returned_state != state {
        return Err(OidcError);
    }
    finish_browser_login(client, client_secret, &code, &verifier)
}

struct Endpoints {
    authorize: String,
    token: String,
    userinfo: String,
}

async fn discover(issuer: &str) -> Result<Endpoints, OidcError> {
    let value: serde_json::Value = reqwest::Client::new()
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| OidcError)?
        .error_for_status()
        .map_err(|_| OidcError)?
        .json()
        .await
        .map_err(|_| OidcError)?;
    Ok(Endpoints {
        authorize: text(&value, "authorization_endpoint")?,
        token: text(&value, "token_endpoint")?,
        userinfo: text(&value, "userinfo_endpoint")?,
    })
}

fn text(value: &serde_json::Value, key: &str) -> Result<String, OidcError> {
    value
        .get(key)
        .and_then(|item| item.as_str())
        .map(str::to_owned)
        .ok_or(OidcError)
}

fn authorization_request(
    endpoint: &str,
    client: &OidcClient,
    challenge: &str,
    state: &str,
) -> String {
    format!(
        "{endpoint}?response_type=code&client_id={}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state={state}&scope=openid%20email",
        client.client_id,
        urlencoding(&client.redirect_uri)
    )
}

async fn drive_login(
    start: String,
    redirect_uri: String,
    username: String,
    password: String,
) -> Result<(String, String), OidcError> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| OidcError)?;
    let mut url = start;
    for _ in 0..6 {
        let response = http.get(&url).send().await.map_err(|_| OidcError)?;
        if response.status().is_redirection() {
            url = location(&url, &response)?;
            if let Some(pair) = callback_code(&url, &redirect_uri) {
                return Ok(pair);
            }
            continue;
        }
        if !response.status().is_success() {
            return Err(OidcError);
        }
        let posted = http
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "login={}&password={}",
                urlencoding(&username),
                urlencoding(&password)
            ))
            .send()
            .await
            .map_err(|_| OidcError)?;
        if !posted.status().is_redirection() {
            return Err(OidcError);
        }
        url = location(&url, &posted)?;
        if let Some(pair) = callback_code(&url, &redirect_uri) {
            return Ok(pair);
        }
    }
    Err(OidcError)
}

fn location(current: &str, response: &reqwest::Response) -> Result<String, OidcError> {
    let header = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .ok_or(OidcError)?;
    if header.starts_with("http://") || header.starts_with("https://") {
        return Ok(header.to_owned());
    }
    let base = reqwest::Url::parse(current).map_err(|_| OidcError)?;
    base.join(header)
        .map(|url| url.to_string())
        .map_err(|_| OidcError)
}

fn callback_code(url: &str, redirect_uri: &str) -> Option<(String, String)> {
    if !url.starts_with(redirect_uri) {
        return None;
    }
    let query = url.split_once('?')?.1;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=')?;
        if name == "code" {
            code = Some(value.to_owned());
        }
        if name == "state" {
            state = Some(value.to_owned());
        }
    }
    Some((code?, state?))
}

async fn read_subject(userinfo: &str, token: &str) -> Result<String, OidcError> {
    let value: serde_json::Value = reqwest::Client::new()
        .get(userinfo)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| OidcError)?
        .error_for_status()
        .map_err(|_| OidcError)?
        .json()
        .await
        .map_err(|_| OidcError)?;
    value
        .get("email")
        .or_else(|| value.get("sub"))
        .and_then(|item| item.as_str())
        .map(str::to_owned)
        .ok_or(OidcError)
}

/// Map an IdP group to a workspace role. `inject` is not a role here.
pub fn role_for_group(group: &str) -> Option<&'static str> {
    match group {
        "credentials-admin" => Some("admin"),
        "credentials-audit" => Some("audit"),
        _ => None,
    }
}

fn urlencoding(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
