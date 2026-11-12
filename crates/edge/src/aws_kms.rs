//! AWS KMS JSON client for a customer-held process or a dev gateway.
//!
//! The hosted control plane must not receive a key policy that allows
//! `kms:Decrypt` on keys that wrap customer secrets. `kms_key_policy`
//! binds decrypt to a Nitro PCR measurement.

use base64::Engine;
use credentials_crypto::{CryptoError, KekContext, RootKeyProvider, RootKeyState};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug)]
pub struct KmsError;

pub struct AwsKms {
    http: reqwest::Client,
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: String,
}

impl AwsKms {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.into().trim_end_matches('/').to_owned(),
            region: region.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
        }
    }

    fn call(
        &self,
        target: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, CryptoError> {
        let payload = serde_json::to_vec(&body).map_err(|_| CryptoError::CorruptStore)?;
        let url = self.endpoint.clone();
        let region = self.region.clone();
        let access = self.access_key.clone();
        let secret = self.secret_key.clone();
        let target = target.to_owned();
        let http = self.http.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("kms runtime")
                        .block_on(async move {
                            let (amz_date, date_stamp) = amz_now();
                            let auth = authorization(
                                "POST",
                                &url,
                                &payload,
                                &region,
                                "kms",
                                &access,
                                &secret,
                                &amz_date,
                                &date_stamp,
                            );
                            http.post(url)
                                .header("Content-Type", "application/x-amz-json-1.1")
                                .header("X-Amz-Target", format!("TrentService.{target}"))
                                .header("X-Amz-Date", amz_date)
                                .header("Authorization", auth)
                                .body(payload)
                                .send()
                                .await
                                .map_err(|_| CryptoError::Io)?
                                .error_for_status()
                                .map_err(|_| CryptoError::RootKeyUnavailable)?
                                .json()
                                .await
                                .map_err(|_| CryptoError::CorruptStore)
                        })
                })
                .join()
                .expect("kms thread")
        })
    }
}

impl RootKeyProvider for AwsKms {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        let value = self.call(
            "CreateKey",
            serde_json::json!({"Description": format!("cred-{workspace_id}")}),
        )?;
        value
            .pointer("/KeyMetadata/KeyId")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or(CryptoError::CorruptStore)
    }

    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        let value = self.call(
            "Encrypt",
            serde_json::json!({
                "KeyId": key_ref,
                "Plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext),
                "EncryptionContext": context_map(context),
            }),
        )?;
        let blob = value
            .get("CiphertextBlob")
            .and_then(|v| v.as_str())
            .ok_or(CryptoError::CorruptStore)?;
        base64::engine::general_purpose::STANDARD
            .decode(blob)
            .map_err(|_| CryptoError::CorruptStore)
    }

    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        context: &KekContext,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
        let value = self.call(
            "Decrypt",
            serde_json::json!({
                "KeyId": key_ref,
                "CiphertextBlob": base64::engine::general_purpose::STANDARD.encode(blob),
                "EncryptionContext": context_map(context),
            }),
        )?;
        let plain = value
            .get("Plaintext")
            .and_then(|v| v.as_str())
            .ok_or(CryptoError::CorruptStore)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(plain)
            .map_err(|_| CryptoError::CorruptStore)?;
        Ok(zeroize::Zeroizing::new(bytes))
    }

    fn schedule_destruction(
        &self,
        key_ref: &str,
        _not_before_unix: u64,
    ) -> Result<(), CryptoError> {
        self.call(
            "ScheduleKeyDeletion",
            serde_json::json!({"KeyId": key_ref, "PendingWindowInDays": 7}),
        )?;
        Ok(())
    }

    fn cancel_destruction(&self, key_ref: &str) -> Result<(), CryptoError> {
        self.call("CancelKeyDeletion", serde_json::json!({"KeyId": key_ref}))?;
        Ok(())
    }

    fn root_key_state(&self, _key_ref: &str) -> Result<RootKeyState, CryptoError> {
        Ok(RootKeyState::Active)
    }

    fn destroy_if_due(&self, _key_ref: &str, _now_unix: u64) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

fn context_map(context: &KekContext) -> serde_json::Value {
    serde_json::json!({
        "purpose": "credentials.kek.v1",
        "workspace_id": context.workspace_id.to_string(),
        "kek_id": context.kek_id.to_string(),
        "kek_version": context.kek_version.to_string(),
    })
}

/// Key policy that allows decrypt only when the Nitro attestation PCR0 matches.
/// The operator's IAM role is not a principal.
pub fn kms_key_policy(pcr0_hex: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EnclaveDecrypt",
            "Effect": "Allow",
            "Principal": {"Service": "kms.amazonaws.com"},
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:PCR0": pcr0_hex
                }
            }
        }]
    })
    .to_string()
}

#[allow(clippy::too_many_arguments)]
pub fn authorization(
    method: &str,
    url: &str,
    payload: &[u8],
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    amz_date: &str,
    date_stamp: &str,
) -> String {
    let parsed = reqwest::Url::parse(url).expect("url");
    let host = parsed.host_str().unwrap_or("localhost");
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let hash = hex_encode(&Sha256::digest(payload));
    let canonical = format!(
        "{method}\n{path}\n\nhost:{host}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n{hash}"
    );
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_encode(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = signing_key(secret_key, date_stamp, region, service);
    let sig = hex_encode(&hmac_sha256(&key, to_sign.as_bytes()));
    key.fill(0);
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders=host;x-amz-date, Signature={sig}"
    )
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request").to_vec()
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    let out = outer.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

pub fn amz_now() -> (String, String) {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    let date = format!("{year:04}{month:02}{day:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    );
    (stamp, date)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_names_pcr0_and_not_an_operator_user() {
        let policy = kms_key_policy("abc");
        assert!(policy.contains("kms:RecipientAttestation:PCR0"));
        assert!(policy.contains("abc"));
        assert!(!policy.contains("arn:aws:iam"));
    }

    #[test]
    fn signature_is_stable_for_the_same_request() {
        let one = authorization(
            "POST",
            "http://127.0.0.1:4566/",
            b"{}",
            "us-east-1",
            "kms",
            "test",
            "test",
            "20130524T000000Z",
            "20130524",
        );
        let two = authorization(
            "POST",
            "http://127.0.0.1:4566/",
            b"{}",
            "us-east-1",
            "kms",
            "test",
            "test",
            "20130524T000000Z",
            "20130524",
        );
        assert_eq!(one, two);
        assert!(one.starts_with("AWS4-HMAC-SHA256 "));
    }
}
