//! Dev Ed25519 JWTs.
//!
//! The signature primitive is `ed25519-dalek`. The JWT encoding is the compact
//! serialization from RFC 7519: this process only accepts `alg=EdDSA` and a
//! single audience. The signing key is generated in process memory. A
//! production issuer would use KMS Sign instead, and startup refuses
//! `CREDENTIALS_ENV=production` because that signer is not in this build.
//!
//! A token carries identity and scope. It does not carry a decryption key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::b64::{b64url_decode, b64url_encode};
use crate::ApiError;

pub const AUDIENCE: &str = "credentials-gateway";
pub const MAX_TTL_SECS: u64 = 15 * 60;
pub const DEFAULT_TTL_SECS: u64 = 5 * 60;
const LEEWAY_SECS: u64 = 30;

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
        let mut seed = [0u8; 32];
        credentials_crypto::random_bytes(&mut seed).map_err(|_| ApiError::KmsUnavailable)?;
        Ok(Self {
            kid: kid.into(),
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn sign(&self, iss: &str, claims: &AgentClaims) -> Result<String, ApiError> {
        if claims.exp <= claims.iat || claims.exp - claims.iat > MAX_TTL_SECS {
            return Err(ApiError::BadRequest);
        }
        let header = format!(
            r#"{{"alg":"EdDSA","kid":"{}","typ":"JWT"}}"#,
            json_escape(&self.kid)
        );
        let wire = WireClaims {
            iss: iss.to_owned(),
            aud: AUDIENCE.to_owned(),
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

    pub fn verify(&self, token: &str, iss: &str, now: u64) -> Result<AgentClaims, ApiError> {
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
        if wire.iss != iss || wire.aud != AUDIENCE {
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
        let token = signer.sign(iss, &claims).unwrap();
        assert!(signer.verify(&token, iss, 100).is_ok());
        assert!(signer.verify(&token, iss, 10_000).is_err());
        assert!(signer.verify(&token, "https://other", 100).is_err());
    }
}
