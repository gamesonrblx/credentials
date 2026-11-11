//! Small HTTP client for the Credentials gateway.
//!
//! The client holds a workspace credential or an agent token. Agent calls
//! attach a DPoP proof signed with `ed25519-dalek`. Secret values are base64
//! on the wire and are not written to logs by this crate.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("the gateway returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("the http client failed")]
    Transport,
    #[error("the response could not be decoded")]
    Decode,
}

pub struct CredentialsClient {
    http: reqwest::Client,
    base: String,
    credential: Option<String>,
}

pub struct DpopKey {
    signing: SigningKey,
    x_b64: String,
}

impl DpopKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("os randomness");
        let signing = SigningKey::from_bytes(&seed);
        let x_b64 = b64url(&signing.verifying_key().to_bytes());
        Self { signing, x_b64 }
    }

    pub fn public_b64(&self) -> &str {
        &self.x_b64
    }

    pub fn proof(&self, htm: &str, htu: &str, access_token: &str) -> String {
        let header = format!(
            r#"{{"alg":"EdDSA","jwk":{{"crv":"Ed25519","kty":"OKP","x":"{}"}},"typ":"dpop+jwt"}}"#,
            self.x_b64
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "ath": b64url(&Sha256::digest(access_token.as_bytes())),
            "jti": Uuid::now_v7().to_string(),
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("dpop payload");
        let signing_input = format!("{}.{}", b64url(header.as_bytes()), b64url(&payload_bytes));
        let signature = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url(&signature.to_bytes()))
    }
}

impl CredentialsClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.into().trim_end_matches('/').to_owned(),
            credential: None,
        }
    }

    pub fn with_credential(mut self, credential: impl Into<String>) -> Self {
        self.credential = Some(credential.into());
        self
    }

    pub async fn create_workspace(&self) -> Result<WorkspaceCreated, ClientError> {
        self.send(self.http.post(format!("{}/v1/workspaces", self.base)), None)
            .await
    }

    pub async fn create_secret(
        &self,
        name: &str,
        value: &[u8],
        hosts: &[&str],
    ) -> Result<VersionCreated, ClientError> {
        let body = serde_json::json!({
            "name": name,
            "value": STANDARD.encode(value),
            "policy": {
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
                "hosts": hosts,
                "allow_proxy": true
            }
        });
        self.send(
            self.http
                .post(format!("{}/v1/secrets", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    pub async fn create_agent(&self, display_name: &str) -> Result<AgentCreated, ClientError> {
        let body = serde_json::json!({ "display_name": display_name });
        self.send(
            self.http
                .post(format!("{}/v1/agents", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    pub async fn create_session(
        &self,
        agent_id: Uuid,
        scopes: &[&str],
        dpop_public_b64: &str,
    ) -> Result<SessionCreated, ClientError> {
        let body = serde_json::json!({
            "agent_id": agent_id,
            "scopes": scopes,
            "ttl_seconds": 300,
            "dpop_public_b64": dpop_public_b64,
        });
        self.send(
            self.http
                .post(format!("{}/v1/agent-sessions", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    pub async fn inject(
        &self,
        token: &str,
        dpop: &str,
        secret: &str,
        url: &str,
        htu: &str,
    ) -> Result<InjectResult, ClientError> {
        let body = serde_json::json!({
            "secret": secret,
            "delivery": "proxy",
            "request": { "method": "POST", "url": url, "body": "" }
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ClientError::Decode)?,
        );
        headers.insert(
            "dpop",
            HeaderValue::from_str(dpop).map_err(|_| ClientError::Decode)?,
        );
        headers.insert(
            "x-dpop-htu",
            HeaderValue::from_str(htu).map_err(|_| ClientError::Decode)?,
        );
        self.send(
            self.http
                .post(format!("{}/v1/inject", self.base))
                .json(&body),
            Some(headers),
        )
        .await
    }

    fn auth(&self) -> Option<HeaderMap> {
        let credential = self.credential.as_ref()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {credential}")).ok()?,
        );
        Some(headers)
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        mut request: reqwest::RequestBuilder,
        headers: Option<HeaderMap>,
    ) -> Result<T, ClientError> {
        if let Some(headers) = headers {
            request = request.headers(headers);
        }
        let response = request.send().await.map_err(|_| ClientError::Transport)?;
        let status = response.status().as_u16();
        let body = response.text().await.map_err(|_| ClientError::Transport)?;
        if !(200..300).contains(&status) {
            return Err(ClientError::Http { status, body });
        }
        if body.is_empty() {
            serde_json::from_str("null").map_err(|_| ClientError::Decode)
        } else {
            serde_json::from_str(&body).map_err(|_| ClientError::Decode)
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceCreated {
    pub id: Uuid,
    pub credential: String,
}

#[derive(Debug, Deserialize)]
pub struct VersionCreated {
    pub secret_id: Uuid,
    pub version_id: Uuid,
    pub version: u32,
}

#[derive(Debug, Deserialize)]
pub struct AgentCreated {
    pub id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct SessionCreated {
    pub session_id: Uuid,
    pub token: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InjectResult {
    pub upstream_status: u16,
    pub body: String,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
