//! HashiCorp Vault Transit. The control plane must not hold this token
//! when the token can decrypt secret-wrapping keys.
//!
//! The base URL must be https unless its host is loopback. The gateway does
//! not use this provider yet. Only the Vault integration test calls it.

use base64::Engine;
use credentials_crypto::{CryptoError, KekContext, RootKeyProvider, RootKeyState};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Vault Transit client. The token is zeroized on drop and never printed.
pub struct VaultTransit {
    http: Option<reqwest::Client>,
    base: String,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for VaultTransit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTransit")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl VaultTransit {
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: crate::net::http_client(),
            base: base.into().trim_end_matches('/').to_owned(),
            token: Zeroizing::new(token.into()),
        }
    }

    fn key_name(workspace_id: Uuid) -> String {
        format!("cred-{workspace_id}")
    }

    /// URL for `/v1/transit/{action}/{key}`, with the key name encoded.
    fn url(&self, action: &str, key_ref: &str) -> Result<String, CryptoError> {
        if !crate::net::is_secure_url(&self.base) {
            return Err(CryptoError::RootKeyUnavailable);
        }
        Ok(format!(
            "{}/v1/transit/{action}/{}",
            self.base,
            crate::net::component(key_ref)
        ))
    }

    fn client(&self) -> Result<reqwest::Client, CryptoError> {
        self.http.clone().ok_or(CryptoError::Io)
    }

    fn block<T: Send>(
        fut: impl std::future::Future<Output = Result<T, CryptoError>> + Send,
    ) -> Result<T, CryptoError> {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| CryptoError::Io)?
                        .block_on(fut)
                })
                .join()
                .unwrap_or(Err(CryptoError::Io))
        })
    }
}

impl RootKeyProvider for VaultTransit {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        let name = Self::key_name(workspace_id);
        let url = self.url("keys", &name)?;
        let token = self.token.as_str();
        let http = self.client()?;
        Self::block(async move {
            http.post(url)
                .header("X-Vault-Token", token)
                .json(&serde_json::json!({"type": "aes256-gcm96"}))
                .send()
                .await
                .map_err(|_| CryptoError::Io)?
                .error_for_status()
                .map_err(|_| CryptoError::RootKeyUnavailable)
        })?;
        Ok(name)
    }

    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        _context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        let url = self.url("encrypt", key_ref)?;
        let body = serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext)
        });
        let token = self.token.as_str();
        let http = self.client()?;
        let text = Self::block(async move {
            let value: serde_json::Value = http
                .post(url)
                .header("X-Vault-Token", token)
                .json(&body)
                .send()
                .await
                .map_err(|_| CryptoError::Io)?
                .error_for_status()
                .map_err(|_| CryptoError::RootKeyUnavailable)?
                .json()
                .await
                .map_err(|_| CryptoError::CorruptStore)?;
            value
                .pointer("/data/ciphertext")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .ok_or(CryptoError::CorruptStore)
        })?;
        Ok(text.into_bytes())
    }

    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        _context: &KekContext,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
        let ciphertext = std::str::from_utf8(blob).map_err(|_| CryptoError::CorruptStore)?;
        let url = self.url("decrypt", key_ref)?;
        let body = serde_json::json!({"ciphertext": ciphertext});
        let token = self.token.as_str();
        let http = self.client()?;
        let plain = Self::block(async move {
            let value: serde_json::Value = http
                .post(url)
                .header("X-Vault-Token", token)
                .json(&body)
                .send()
                .await
                .map_err(|_| CryptoError::Io)?
                .error_for_status()
                .map_err(|_| CryptoError::RootKeyUnavailable)?
                .json()
                .await
                .map_err(|_| CryptoError::CorruptStore)?;
            let encoded = value
                .pointer("/data/plaintext")
                .and_then(|v| v.as_str())
                .ok_or(CryptoError::CorruptStore)?;
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| CryptoError::CorruptStore)
        })?;
        Ok(zeroize::Zeroizing::new(plain))
    }

    fn schedule_destruction(
        &self,
        _key_ref: &str,
        _not_before_unix: u64,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::RootKeyUnavailable)
    }

    fn cancel_destruction(&self, _key_ref: &str) -> Result<(), CryptoError> {
        Err(CryptoError::RootKeyUnavailable)
    }

    fn root_key_state(&self, _key_ref: &str) -> Result<RootKeyState, CryptoError> {
        Ok(RootKeyState::Active)
    }

    fn destroy_if_due(&self, _key_ref: &str, _now_unix: u64) -> Result<bool, CryptoError> {
        Ok(false)
    }
}
