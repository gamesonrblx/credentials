//! Ed25519 JWTs, audit checkpoints, and end-to-end release grants.
//!
//! The signature primitive is `ed25519-dalek`. The JWT encoding is the compact
//! serialization from RFC 7519: this process only accepts `alg=EdDSA` and a
//! single audience. Dev builds keep the seed in memory or in a file marked
//! DEV ONLY. With `CREDENTIALS_ENV=production` the control plane loads its
//! seed from a separate file through [`DevSigner::load_production`]; there is
//! no KMS Sign backend in this build.
//!
//! A token carries identity and scope. It does not carry a decryption key.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use credentials_crypto::DevPolicy;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::b64::{b64url_decode, b64url_encode};
use crate::ApiError;

pub const AUDIENCE: &str = "credentials-gateway";
pub const MAX_TTL_SECS: u64 = 15 * 60;
pub const DEFAULT_TTL_SECS: u64 = 5 * 60;
const LEEWAY_SECS: u64 = 30;

/// Domain prefix for an end-to-end release grant. The signed message is this
/// prefix followed by the exact grant JSON bytes.
pub const GRANT_PREFIX: &[u8] = b"credentials.grant.v1\n";

/// The bytes a grant signature covers.
pub fn grant_message(grant_json: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(GRANT_PREFIX.len() + grant_json.len());
    message.extend_from_slice(GRANT_PREFIX);
    message.extend_from_slice(grant_json);
    message
}

pub struct DevSigner {
    pub kid: String,
    signing: SigningKey,
}

#[derive(Clone, Debug)]
pub struct AgentClaims {
    pub exp: u64,
    pub iat: u64,
    pub jti: Uuid,
    pub workspace_id: Uuid,
    pub agent_id: Uuid,
    pub session_id: Uuid,
    pub scopes: Vec<String>,
    pub jkt: String,
}

#[derive(Serialize, Deserialize)]
struct WireClaims {
    iss: String,
    aud: String,
    sub: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    jti: String,
    workspace_id: String,
    agent_id: String,
    session_id: String,
    scopes: Vec<String>,
    cnf: Cnf,
}

#[derive(Serialize, Deserialize)]
struct Cnf {
    jkt: String,
}

impl DevSigner {
    pub fn generate(kid: impl Into<String>) -> Result<Self, ApiError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        credentials_crypto::random_bytes(seed.as_mut_slice())
            .map_err(|_| ApiError::KmsUnavailable)?;
        Ok(Self::from_seed(kid, seed.as_slice()))
    }

    /// Signing seed for the production control plane. Refused in dev, and
    /// refused if the file is a dev signer seed. This key signs tokens and
    /// audit tips. It does not unwrap secrets.
    pub fn load_production(path: &Path, policy: DevPolicy) -> Result<Self, ApiError> {
        if policy.allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
        if path.exists() {
            let bytes = fs::read(path).map_err(|_| ApiError::KmsUnavailable)?;
            let file: SignerFile =
                serde_json::from_slice(&bytes).map_err(|_| ApiError::KmsUnavailable)?;
            if file.warning.contains("DEV ONLY") {
                return Err(ApiError::KmsUnavailable);
            }
            let seed =
                Zeroizing::new(hex_decode(&file.seed_hex).map_err(|_| ApiError::KmsUnavailable)?);
            if seed.len() != 32 {
                return Err(ApiError::KmsUnavailable);
            }
            return Ok(Self::from_seed(file.kid, seed.as_slice()));
        }
        let signer = Self::generate("sign-1")?;
        let seed = signer.signing.to_bytes();
        let file = SignerFile {
            warning: "Signing seed for tokens and audit tips. Not a secret-unwrapping key."
                .to_owned(),
            kid: signer.kid.clone(),
            seed_hex: hex_encode(&seed),
        };
        Self::write_seed(path, &file)?;
        Ok(signer)
    }

    /// Dev signing seed on disk. Refused when `CREDENTIALS_ENV=production`.
    /// The database must not hold this seed.
    pub fn load_or_create(path: &Path, policy: DevPolicy) -> Result<Self, ApiError> {
        if !policy.allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
        if path.exists() {
            let bytes = fs::read(path).map_err(|_| ApiError::KmsUnavailable)?;
            let file: SignerFile =
                serde_json::from_slice(&bytes).map_err(|_| ApiError::KmsUnavailable)?;
            let seed =
                Zeroizing::new(hex_decode(&file.seed_hex).map_err(|_| ApiError::KmsUnavailable)?);
            if seed.len() != 32 {
                return Err(ApiError::KmsUnavailable);
            }
            return Ok(Self::from_seed(file.kid, seed.as_slice()));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| ApiError::KmsUnavailable)?;
            }
        }
        let signer = Self::generate("dev-1")?;
        let seed = signer.signing.to_bytes();
        let file = SignerFile {
            warning: "DEV ONLY. Not for production. This file contains a raw signing seed."
                .to_owned(),
            kid: signer.kid.clone(),
            seed_hex: hex_encode(&seed),
        };
        Self::write_seed(path, &file)?;
        Ok(signer)
    }

    fn from_seed(kid: impl Into<String>, seed: &[u8]) -> Self {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&seed[..32]);
        Self {
            kid: kid.into(),
            signing: SigningKey::from_bytes(&raw),
        }
    }

    /// Sign raw bytes with the gateway key.
    ///
    /// One Ed25519 key signs three kinds of message, and each is
    /// domain-separated: audit checkpoints start with
    /// `CHECKPOINT_PREFIX` (anchor.rs), release grants start with
    /// [`GRANT_PREFIX`], and JWTs sign `base64url(header).base64url(payload)`,
    /// which starts with `eyJ` and so cannot begin with either prefix. A
    /// caller must not pass a message without one of these framings.
    pub fn sign_message(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }

    /// Sign a release grant: `GRANT_PREFIX || grant_json`.
    pub fn sign_grant(&self, grant_json: &[u8]) -> Vec<u8> {
        self.sign_message(&grant_message(grant_json))
    }

    /// The 32-byte Ed25519 public key. Published at `GET /v1/keys`.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn write_seed(path: &Path, file: &SignerFile) -> Result<(), ApiError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| ApiError::KmsUnavailable)?;
            }
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|_| ApiError::KmsUnavailable)?;
        let tmp = path.with_extension("tmp");
        {
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut out = options.open(&tmp).map_err(|_| ApiError::KmsUnavailable)?;
            out.write_all(&bytes)
                .map_err(|_| ApiError::KmsUnavailable)?;
            out.sync_all().map_err(|_| ApiError::KmsUnavailable)?;
        }
        fs::rename(&tmp, path).map_err(|_| ApiError::KmsUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn verify_message(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        self.signing
            .verifying_key()
            .verify(message, &Signature::from_bytes(&bytes))
            .is_ok()
    }

    pub fn sign(&self, iss: &str, aud: &str, claims: &AgentClaims) -> Result<String, ApiError> {
        if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_TTL_SECS {
            return Err(ApiError::BadRequest);
        }
        let header = format!(
            r#"{{"alg":"EdDSA","kid":"{}","typ":"JWT"}}"#,
            json_escape(&self.kid)
        );
        let wire = WireClaims {
            iss: iss.to_owned(),
            aud: aud.to_owned(),
            sub: format!("agent:{}", claims.agent_id),
            iat: claims.iat,
            nbf: claims.iat,
            exp: claims.exp,
            jti: claims.jti.to_string(),
            workspace_id: claims.workspace_id.to_string(),
            agent_id: claims.agent_id.to_string(),
            session_id: claims.session_id.to_string(),
            scopes: claims.scopes.clone(),
            cnf: Cnf {
                jkt: claims.jkt.clone(),
            },
        };
        let payload = serde_json::to_vec(&wire).map_err(|_| ApiError::BadRequest)?;
        let signing_input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(&payload)
        );
        let signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            b64url_encode(&signature.to_bytes())
        ))
    }

    pub fn verify(
        &self,
        token: &str,
        iss: &str,
        aud: &str,
        now: u64,
    ) -> Result<AgentClaims, ApiError> {
        let (header_b64, payload_b64, sig_b64) = split_jwt(token)?;
        let header: serde_json::Value = serde_json::from_slice(&b64url_decode(header_b64)?)
            .map_err(|_| ApiError::Unauthenticated)?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
            return Err(ApiError::Unauthenticated);
        }
        if header.get("kid").and_then(|v| v.as_str()) != Some(self.kid.as_str()) {
            return Err(ApiError::Unauthenticated);
        }
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = b64url_decode(sig_b64)?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::Unauthenticated)?;
        let signature = Signature::from_bytes(&sig_array);
        self.signing
            .verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| ApiError::Unauthenticated)?;
        let wire: WireClaims = serde_json::from_slice(&b64url_decode(payload_b64)?)
            .map_err(|_| ApiError::Unauthenticated)?;
        if wire.iss != iss || wire.aud != aud {
            return Err(ApiError::Unauthenticated);
        }
        if wire.exp <= wire.iat || wire.exp - wire.iat > MAX_TTL_SECS {
            return Err(ApiError::Unauthenticated);
        }
        if now.saturating_add(LEEWAY_SECS) < wire.nbf || wire.exp.saturating_add(LEEWAY_SECS) < now
        {
            return Err(ApiError::Unauthenticated);
        }
        let agent_id = Uuid::parse_str(&wire.agent_id).map_err(|_| ApiError::Unauthenticated)?;
        if wire.sub != format!("agent:{agent_id}") {
            return Err(ApiError::Unauthenticated);
        }
        Ok(AgentClaims {
            exp: wire.exp,
            iat: wire.iat,
            jti: Uuid::parse_str(&wire.jti).map_err(|_| ApiError::Unauthenticated)?,
            workspace_id: Uuid::parse_str(&wire.workspace_id)
                .map_err(|_| ApiError::Unauthenticated)?,
            agent_id,
            session_id: Uuid::parse_str(&wire.session_id).map_err(|_| ApiError::Unauthenticated)?,
            scopes: wire.scopes,
            jkt: wire.cnf.jkt,
        })
    }
}

fn split_jwt(token: &str) -> Result<(&str, &str, &str), ApiError> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or(ApiError::Unauthenticated)?;
    let payload = parts.next().ok_or(ApiError::Unauthenticated)?;
    let sig = parts.next().ok_or(ApiError::Unauthenticated)?;
    if parts.next().is_some() || header.is_empty() || payload.is_empty() || sig.is_empty() {
        return Err(ApiError::Unauthenticated);
    }
    Ok((header, payload, sig))
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Serialize, Deserialize)]
struct SignerFile {
    warning: String,
    kid: String,
    seed_hex: String,
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

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_token_is_rejected() {
        let signer = DevSigner::generate("dev-1").unwrap();
        let claims = AgentClaims {
            exp: 200,
            iat: 100,
            jti: Uuid::now_v7(),
            workspace_id: Uuid::now_v7(),
            agent_id: Uuid::now_v7(),
            session_id: Uuid::now_v7(),
            scopes: vec!["secret:inject:prod/a".into()],
            jkt: "thumb".into(),
        };
        let iss = "https://credentials.local/v1";
        let token = signer.sign(iss, AUDIENCE, &claims).unwrap();
        assert!(signer.verify(&token, iss, AUDIENCE, 100).is_ok());
        assert!(signer.verify(&token, iss, AUDIENCE, 10_000).is_err());
        assert!(signer
            .verify(&token, "https://other", AUDIENCE, 100)
            .is_err());
        assert!(signer.verify(&token, iss, "other-aud", 100).is_err());
    }

    #[test]
    fn grant_signature_is_domain_separated() {
        let signer = DevSigner::generate("sign-1").unwrap();
        let grant = br#"{"v":1}"#;
        let signature = signer.sign_grant(grant);
        assert!(signer.verify_message(&grant_message(grant), &signature));
        assert!(!signer.verify_message(grant, &signature));
        let key = ed25519_dalek::VerifyingKey::from_bytes(&signer.public_key()).unwrap();
        let sig = Signature::from_bytes(&<[u8; 64]>::try_from(signature.as_slice()).unwrap());
        assert!(key.verify(&grant_message(grant), &sig).is_ok());
    }
}
