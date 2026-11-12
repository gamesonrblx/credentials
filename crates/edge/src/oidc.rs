//! OIDC authorization code with PKCE.
//!
//! SAML is not implemented. A human session from this flow is an admin
//! capability. It is not a decryption key.

use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct OidcError;

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
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scope=openid",
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
) -> Result<String, OidcError> {
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}&code_verifier={verifier}",
        urlencoding(&client.redirect_uri),
        client.client_id
    );
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
