//! Small HTTP client for the Credentials gateway.
//!
//! The client holds a workspace credential or an agent token. Agent calls
//! attach a DPoP proof signed with `ed25519-dalek`. Secret values are base64
//! on the wire and are not written to logs by this crate.

mod tls;

pub use tls::{hybrid_config, hybrid_http, HYBRID_GROUP};

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
            http: tls::hybrid_http(false),
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

    pub async fn create_version(
        &self,
        name: &str,
        value: &[u8],
    ) -> Result<VersionCreated, ClientError> {
        let body = serde_json::json!({ "value": STANDARD.encode(value) });
        self.send(
            self.http
                .post(format!("{}/v1/secrets/{name}/versions", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    pub async fn disable_secret(&self, name: &str) -> Result<(), ClientError> {
        self.send_empty(
            self.http
                .post(format!("{}/v1/secrets/{name}/disable", self.base))
                .json(&serde_json::json!({})),
            self.auth(),
        )
        .await
    }

    pub async fn revoke_session(&self, session_id: Uuid) -> Result<(), ClientError> {
        self.send_empty(
            self.http.post(format!(
                "{}/v1/agent-sessions/{session_id}/revoke",
                self.base
            )),
            self.auth(),
        )
        .await
    }

    pub async fn delete_workspace(&self, id: Uuid) -> Result<(), ClientError> {
        let body = serde_json::json!({ "confirm": id });
        self.send_empty(
            self.http
                .post(format!("{}/v1/workspaces/{id}/deletion", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    pub async fn cancel_deletion(&self, id: Uuid) -> Result<(), ClientError> {
        self.send_empty(
            self.http
                .post(format!("{}/v1/workspaces/{id}/deletion/cancel", self.base))
                .json(&serde_json::json!({})),
            self.auth(),
        )
        .await
    }

    pub async fn list_sessions(&self) -> Result<SessionList, ClientError> {
        self.send(
            self.http.get(format!("{}/v1/agent-sessions", self.base)),
            self.auth(),
        )
        .await
    }

    pub async fn audit(&self, agent_id: Option<Uuid>) -> Result<AuditPage, ClientError> {
        let mut url = format!("{}/v1/audit", self.base);
        if let Some(agent_id) = agent_id {
            url.push_str(&format!("?agent_id={agent_id}"));
        }
        self.send(self.http.get(url), self.auth()).await
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

    /// Proxy injection: `POST` to `url` with an empty body. `content_type`, when
    /// given, is sent as the inject body's `content_type` field. The gateway
    /// derives DPoP `htu` from the request it receives.
    ///
    /// For an end-to-end secret, `InjectResult::body` is the base64 of the
    /// signed grant that `credentials-injector deliver` consumes.
    pub async fn inject(
        &self,
        token: &str,
        dpop: &str,
        secret: &str,
        url: &str,
        content_type: Option<&str>,
    ) -> Result<InjectResult, ClientError> {
        let mut body = serde_json::json!({
            "secret": secret,
            "delivery": "proxy",
            "request": { "method": "POST", "url": url, "body": "" }
        });
        if let Some(content_type) = content_type {
            body["content_type"] = serde_json::Value::from(content_type);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ClientError::Decode)?,
        );
        headers.insert(
            "dpop",
            HeaderValue::from_str(dpop).map_err(|_| ClientError::Decode)?,
        );
        self.send(
            self.http
                .post(format!("{}/v1/inject", self.base))
                .json(&body),
            Some(headers),
        )
        .await
    }

    /// `GET /v1/keys`: the control-plane keys that sign end-to-end grants.
    pub async fn control_plane_keys(&self) -> Result<ControlPlaneKeys, ClientError> {
        self.send(self.http.get(format!("{}/v1/keys", self.base)), self.auth())
            .await
    }

    /// `POST /v1/workspace-keys`: register the workspace X-Wing encapsulation key.
    pub async fn register_workspace_key(
        &self,
        encapsulation_key: &[u8],
    ) -> Result<WorkspaceKey, ClientError> {
        let body = serde_json::json!({ "encapsulation_key": STANDARD.encode(encapsulation_key) });
        self.send(
            self.http
                .post(format!("{}/v1/workspace-keys", self.base))
                .json(&body),
            self.auth(),
        )
        .await
    }

    /// `GET /v1/workspace-keys`: the registered encapsulation key.
    pub async fn workspace_key(&self) -> Result<WorkspaceKey, ClientError> {
        self.send(
            self.http.get(format!("{}/v1/workspace-keys", self.base)),
            self.auth(),
        )
        .await
    }

    /// `POST /v1/e2e-secrets`: store a value the caller already sealed.
    /// The request carries ciphertext only.
    pub async fn store_e2e_secret(
        &self,
        upload: &E2eSecretUpload<'_>,
    ) -> Result<VersionCreated, ClientError> {
        let body = serde_json::json!({
            "name": upload.name,
            "secret_id": upload.secret_id,
            "version_id": upload.version_id,
            "workspace_key_id": upload.workspace_key_id,
            "payload_nonce": STANDARD.encode(upload.payload_nonce),
            "payload_ciphertext": STANDARD.encode(upload.payload_ciphertext),
            "dek_wrap_nonce": STANDARD.encode(upload.dek_wrap_nonce),
            "dek_wrapped": STANDARD.encode(upload.dek_wrapped),
            "e2e_encapsulation": STANDARD.encode(upload.encapsulation),
            "plaintext_len": upload.plaintext_len,
            "policy": upload.policy,
        });
        self.send(
            self.http
                .post(format!("{}/v1/e2e-secrets", self.base))
                .json(&body),
            self.auth(),
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

    async fn send_empty(
        &self,
        request: reqwest::RequestBuilder,
        headers: Option<HeaderMap>,
    ) -> Result<(), ClientError> {
        let _: serde_json::Value = self.send(request, headers).await?;
        Ok(())
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

/// Response of `GET /v1/keys`.
#[derive(Debug, Deserialize)]
pub struct ControlPlaneKeys {
    pub keys: Vec<ControlPlaneKey>,
}

#[derive(Debug, Deserialize)]
pub struct ControlPlaneKey {
    pub kid: String,
    pub alg: String,
    /// Standard base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
}

impl ControlPlaneKey {
    /// The raw Ed25519 key. Fails unless `alg` is `EdDSA` and the key is 32 bytes.
    pub fn public_key_bytes(&self) -> Result<[u8; 32], ClientError> {
        if self.alg != "EdDSA" {
            return Err(ClientError::Decode);
        }
        STANDARD
            .decode(&self.public_key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(ClientError::Decode)
    }
}

/// Response of `GET` and `POST /v1/workspace-keys`. `encapsulation_key` is base64.
#[derive(Debug, Deserialize)]
pub struct WorkspaceKey {
    pub id: Uuid,
    pub encapsulation_key: String,
}

/// Delivery policy as the gateway accepts it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DeliveryPolicy {
    pub header_name: Option<String>,
    pub header_format: Option<String>,
    pub env_name: Option<String>,
    pub hosts: Vec<String>,
    pub allow_proxy: bool,
    pub allow_header: bool,
    pub allow_env: bool,
}

/// Ciphertext columns for one sealed secret. There is no plaintext field.
#[derive(Clone, Debug)]
pub struct E2eSecretUpload<'a> {
    pub name: &'a str,
    pub secret_id: Uuid,
    pub version_id: Uuid,
    pub workspace_key_id: Uuid,
    pub payload_nonce: [u8; 12],
    pub payload_ciphertext: &'a [u8],
    pub dek_wrap_nonce: [u8; 12],
    pub dek_wrapped: &'a [u8],
    pub encapsulation: &'a [u8],
    pub plaintext_len: usize,
    pub policy: &'a DeliveryPolicy,
}

#[derive(Debug, Deserialize)]
pub struct SessionList {
    pub sessions: Vec<SessionItem>,
}

#[derive(Debug, Deserialize)]
pub struct SessionItem {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
}

#[derive(Debug, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub event_type: String,
    pub hash_hex: String,
    pub prev_hash_hex: String,
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_key_decodes_only_32_byte_eddsa_keys() {
        let key = ControlPlaneKey {
            kid: "cp-1".into(),
            alg: "EdDSA".into(),
            public_key: STANDARD.encode([5u8; 32]),
        };
        assert_eq!(key.public_key_bytes().unwrap(), [5u8; 32]);
        let short = ControlPlaneKey {
            public_key: STANDARD.encode([5u8; 31]),
            ..key
        };
        assert!(short.public_key_bytes().is_err());
        let other_alg = ControlPlaneKey {
            alg: "ES256".into(),
            public_key: STANDARD.encode([5u8; 32]),
            kid: "cp-2".into(),
        };
        assert!(other_alg.public_key_bytes().is_err());
    }
}
