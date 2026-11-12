//! AWS KMS JSON client for a customer-held process or a dev gateway.
//!
//! The hosted control plane must not receive a key policy that allows
//! `kms:Decrypt` on keys that wrap customer secrets. `kms_key_policy`
//! binds decrypt to one role and a Nitro PCR measurement.
//!
//! The gateway does not use this client yet. Only tests call it.

use base64::Engine;
use credentials_crypto::{CryptoError, KekContext, RootKeyProvider, RootKeyState};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug)]
pub struct KmsError;

/// AWS KMS JSON client. The secret access key and session token are
/// zeroized on drop and never printed by `Debug`.
pub struct AwsKms {
    http: reqwest::Client,
    endpoint: String,
    region: String,
    access_key: String,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for AwsKms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKms")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AwsKms {
    pub fn new(
        endpoint: impl Into<String>,
        region: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            endpoint: endpoint.into().trim_end_matches('/').to_owned(),
            region: region.into(),
            access_key: access_key.into(),
            secret_key: Zeroizing::new(secret_key.into()),
            session_token: None,
        }
    }

    /// Use temporary credentials (an assumed role, IRSA or an instance
    /// profile). The token is sent as `X-Amz-Security-Token` and signed.
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(Zeroizing::new(token.into()));
        self
    }

    fn call(
        &self,
        target: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, CryptoError> {
        let payload = serde_json::to_vec(&body).map_err(|_| CryptoError::CorruptStore)?;
        let url = self.endpoint.as_str();
        let token = self.session_token.as_ref().map(|token| token.as_str());
        let http = self.http.clone();
        std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| CryptoError::Io)?
                        .block_on(async move {
                            let (amz_date, date_stamp) = amz_now();
                            let auth = authorization_with_token(
                                "POST",
                                url,
                                &payload,
                                &self.region,
                                "kms",
                                &self.access_key,
                                &self.secret_key,
                                token,
                                &amz_date,
                                &date_stamp,
                            );
                            let mut request = http
                                .post(url)
                                .header("Content-Type", "application/x-amz-json-1.1")
                                .header("X-Amz-Target", format!("TrentService.{target}"))
                                .header("X-Amz-Date", amz_date)
                                .header("Authorization", auth);
                            if let Some(token) = token {
                                request = request.header("X-Amz-Security-Token", token);
                            }
                            request
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
                .unwrap_or(Err(CryptoError::Io))
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

/// Key policy for a customer-held KMS key.
///
/// `admin_principal_arn` (usually `arn:aws:iam::<account>:root`) may manage
/// the key but is not granted `kms:Decrypt`, `kms:Encrypt` or data-key
/// actions. `decrypt_role_arn` may call `kms:Decrypt` only with a Nitro
/// attestation whose PCR0 equals `pcr0_hex`, and may encrypt freely.
///
/// An admin with `kms:PutKeyPolicy` can still rewrite this policy. That is
/// AWS's model, and CloudTrail records it.
pub fn kms_key_policy(admin_principal_arn: &str, decrypt_role_arn: &str, pcr0_hex: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "KeyAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": admin_principal_arn},
                "Action": [
                    "kms:Create*",
                    "kms:Describe*",
                    "kms:Enable*",
                    "kms:List*",
                    "kms:Put*",
                    "kms:Update*",
                    "kms:Revoke*",
                    "kms:Disable*",
                    "kms:Get*",
                    "kms:Delete*",
                    "kms:TagResource",
                    "kms:UntagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:CancelKeyDeletion"
                ],
                "Resource": "*"
            },
            {
                "Sid": "RoleEncrypt",
                "Effect": "Allow",
                "Principal": {"AWS": decrypt_role_arn},
                "Action": "kms:Encrypt",
                "Resource": "*"
            },
            {
                "Sid": "EnclaveDecrypt",
                "Effect": "Allow",
                "Principal": {"AWS": decrypt_role_arn},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        "kms:RecipientAttestation:PCR0": pcr0_hex
                    }
                }
            }
        ]
    })
    .to_string()
}

/// SigV4 `Authorization` header for long-lived credentials.
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
    authorization_with_token(
        method, url, payload, region, service, access_key, secret_key, None, amz_date, date_stamp,
    )
}

/// SigV4 `Authorization` header. With a session token, the caller must send
/// it as `X-Amz-Security-Token`; it is part of the signed headers.
/// The host includes a non-default port, as the HTTP `Host` header does.
#[allow(clippy::too_many_arguments)]
pub fn authorization_with_token(
    method: &str,
    url: &str,
    payload: &[u8],
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    amz_date: &str,
    date_stamp: &str,
) -> String {
    let (host, path) = host_and_path(url);
    let hash = hex_encode(&Sha256::digest(payload));
    let (token_header, signed) = match session_token {
        Some(token) => (
            format!("x-amz-security-token:{}\n", token.trim()),
            "host;x-amz-date;x-amz-security-token",
        ),
        None => (String::new(), "host;x-amz-date"),
    };
    let canonical = Zeroizing::new(format!(
        "{method}\n{path}\n\nhost:{host}\nx-amz-date:{amz_date}\n{token_header}\n{signed}\n{hash}"
    ));
    drop(Zeroizing::new(token_header));
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_encode(&Sha256::digest(canonical.as_bytes()))
    );
    let key = signing_key(secret_key, date_stamp, region, service);
    let sig = hex_encode(&hmac_sha256(key.as_slice(), to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    )
}

/// Host (with a non-default port) and path of `url`. An unparsable URL
/// yields an empty host, so the signature cannot match any real request.
fn host_and_path(url: &str) -> (String, String) {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return (String::new(), "/".to_owned());
    };
    let name = parsed.host_str().unwrap_or("");
    let host = match parsed.port() {
        Some(port) => format!("{name}:{port}"),
        None => name.to_owned(),
    };
    let path = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };
    (host, path)
}

/// SigV4 for S3. The host includes the port, and every `x-amz-*` header is signed.
/// S3 rejects a request that omits `x-amz-content-sha256` or leaves an `x-amz-*` header unsigned.
#[allow(clippy::too_many_arguments)]
pub fn s3_authorization(
    method: &str,
    url: &str,
    payload: &[u8],
    region: &str,
    access_key: &str,
    secret_key: &str,
    amz_date: &str,
    date_stamp: &str,
    extra: &[(&str, &str)],
) -> (String, String) {
    let (host, path) = host_and_path(url);
    let hash = hex_encode(&Sha256::digest(payload));
    let mut headers = vec![
        ("host".to_owned(), host),
        ("x-amz-content-sha256".to_owned(), hash.clone()),
        ("x-amz-date".to_owned(), amz_date.to_owned()),
    ];
    for (name, value) in extra {
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical_headers = String::new();
    let mut signed = String::new();
    for (index, (name, value)) in headers.iter().enumerate() {
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
        if index > 0 {
            signed.push(';');
        }
        signed.push_str(name);
    }
    let canonical = format!("{method}\n{path}\n\n{canonical_headers}\n{signed}\n{hash}");
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_encode(&Sha256::digest(canonical.as_bytes()))
    );
    let key = signing_key(secret_key, date_stamp, region, "s3");
    let sig = hex_encode(&hmac_sha256(key.as_slice(), to_sign.as_bytes()));
    (
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
        ),
        hash,
    )
}

/// Derive the SigV4 signing key. Every intermediate key is zeroized.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Zeroizing<[u8; 32]> {
    let seed = Zeroizing::new(format!("AWS4{secret}"));
    let mut k_date = hmac_sha256(seed.as_bytes(), date.as_bytes());
    let mut k_region = hmac_sha256(&k_date, region.as_bytes());
    let mut k_service = hmac_sha256(&k_region, service.as_bytes());
    let key = Zeroizing::new(hmac_sha256(&k_service, b"aws4_request"));
    k_date.zeroize();
    k_region.zeroize();
    k_service.zeroize();
    key
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
    block.zeroize();
    ipad.zeroize();
    opad.zeroize();
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

    const ADMIN: &str = "arn:aws:iam::111122223333:root";
    const ROLE: &str = "arn:aws:iam::111122223333:role/enclave";

    #[test]
    fn policy_grants_decrypt_to_the_role_only_with_pcr0() {
        let policy: serde_json::Value =
            serde_json::from_str(&kms_key_policy(ADMIN, ROLE, "abc")).unwrap();
        assert_eq!(policy["Version"], "2012-10-17");
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements.len(), 3);
        for statement in statements {
            assert!(statement["Principal"].get("Service").is_none());
            assert!(statement["Principal"]["AWS"].is_string());
        }
        let admin = &statements[0];
        assert_eq!(admin["Principal"]["AWS"], ADMIN);
        let admin_actions: Vec<&str> = admin["Action"]
            .as_array()
            .unwrap()
            .iter()
            .map(|action| action.as_str().unwrap())
            .collect();
        assert!(admin_actions.contains(&"kms:Put*"));
        for forbidden in [
            "kms:*",
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:ReEncrypt*",
        ] {
            assert!(!admin_actions.contains(&forbidden));
        }
        let encrypt = &statements[1];
        assert_eq!(encrypt["Principal"]["AWS"], ROLE);
        assert_eq!(encrypt["Action"], "kms:Encrypt");
        let decrypt = &statements[2];
        assert_eq!(decrypt["Principal"]["AWS"], ROLE);
        assert_eq!(decrypt["Action"], "kms:Decrypt");
        assert_eq!(
            decrypt["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"],
            "abc"
        );
    }

    #[test]
    fn debug_hides_the_secret_key_and_session_token() {
        let kms = AwsKms::new(
            "https://kms.us-east-1.amazonaws.com",
            "us-east-1",
            "AKID",
            "very-secret",
        )
        .with_session_token("session-secret");
        let shown = format!("{kms:?}");
        assert!(shown.contains("AKID"));
        assert!(!shown.contains("very-secret"));
        assert!(!shown.contains("session-secret"));
    }

    /// AWS SigV4 test suite, `get-vanilla`.
    #[test]
    fn signature_matches_the_aws_get_vanilla_vector() {
        let header = authorization(
            "GET",
            "https://example.amazonaws.com/",
            b"",
            "us-east-1",
            "service",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(
            header,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn a_session_token_is_signed() {
        let args = (
            "POST",
            "https://kms.us-east-1.amazonaws.com/",
            b"{}".as_slice(),
            "us-east-1",
            "kms",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        );
        let plain = authorization_with_token(
            args.0,
            args.1,
            args.2,
            args.3,
            args.4,
            args.5,
            args.6,
            None,
            "20150830T123600Z",
            "20150830",
        );
        let with_token = authorization_with_token(
            args.0,
            args.1,
            args.2,
            args.3,
            args.4,
            args.5,
            args.6,
            Some("token-a"),
            "20150830T123600Z",
            "20150830",
        );
        let other_token = authorization_with_token(
            args.0,
            args.1,
            args.2,
            args.3,
            args.4,
            args.5,
            args.6,
            Some("token-b"),
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(
            plain,
            authorization(
                args.0,
                args.1,
                args.2,
                args.3,
                args.4,
                args.5,
                args.6,
                "20150830T123600Z",
                "20150830"
            )
        );
        assert!(with_token.contains("SignedHeaders=host;x-amz-date;x-amz-security-token,"));
        assert!(!with_token.contains("token-a"));
        assert_ne!(signature_of(&plain), signature_of(&with_token));
        assert_ne!(signature_of(&with_token), signature_of(&other_token));
        // Known answer, computed from the canonical request below with the
        // same secret, so a change to the token canonicalisation is caught.
        let canonical = "POST\n/\n\nhost:kms.us-east-1.amazonaws.com\nx-amz-date:20150830T123600Z\nx-amz-security-token:token-a\n\nhost;x-amz-date;x-amz-security-token\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
        let scope = "20150830/us-east-1/kms/aws4_request";
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n{scope}\n{}",
            hex_encode(&Sha256::digest(canonical.as_bytes()))
        );
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "kms",
        );
        assert_eq!(
            signature_of(&with_token),
            hex_encode(&hmac_sha256(key.as_slice(), to_sign.as_bytes()))
        );
    }

    fn signature_of(header: &str) -> String {
        header.rsplit("Signature=").next().unwrap().to_owned()
    }

    #[test]
    fn the_signed_host_keeps_a_non_default_port() {
        assert_eq!(
            host_and_path("http://127.0.0.1:4566"),
            ("127.0.0.1:4566".to_owned(), "/".to_owned())
        );
        assert_eq!(
            host_and_path("https://kms.us-east-1.amazonaws.com/"),
            ("kms.us-east-1.amazonaws.com".to_owned(), "/".to_owned())
        );
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

    #[test]
    fn s3_signature_signs_the_lock_header_and_the_port() {
        let (header, hash) = s3_authorization(
            "PUT",
            "http://127.0.0.1:9000/lock-bucket",
            b"",
            "us-east-1",
            "minioadmin",
            "minioadmin",
            "20130524T000000Z",
            "20130524",
            &[("x-amz-bucket-object-lock-enabled", "true")],
        );
        assert!(header.contains(
            "SignedHeaders=host;x-amz-bucket-object-lock-enabled;x-amz-content-sha256;x-amz-date"
        ));
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
