//! HashiCorp Vault Transit. The control plane must not hold this token
//! when the token can decrypt secret-wrapping keys.

use base64::Engine;
use credentials_crypto::{CryptoError, KekContext, RootKeyProvider, RootKeyState};
use uuid::Uuid;

pub struct VaultTransit {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl VaultTransit {
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.into().trim_end_matches('/').to_owned(),
            token: token.into(),
        }
    }

    fn key_name(workspace_id: Uuid) -> String {
        format!("cred-{workspace_id}")
    }

    fn block<T: Send>(fut: impl std::future::Future<Output = T> + Send) -> T {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("vault runtime")
                        .block_on(fut)
                })
                .join()
                .expect("vault thread")
        })
    }
}

impl RootKeyProvider for VaultTransit {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        let name = Self::key_name(workspace_id);
        let url = format!("{}/v1/transit/keys/{name}", self.base);
        let token = self.token.clone();
        let http = self.http.clone();
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
        let url = format!("{}/v1/transit/encrypt/{key_ref}", self.base);
        let body = serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext)
        });
        let token = self.token.clone();
        let http = self.http.clone();
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
        let url = format!("{}/v1/transit/decrypt/{key_ref}", self.base);
        let body = serde_json::json!({"ciphertext": ciphertext});
        let token = self.token.clone();
        let http = self.http.clone();
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
