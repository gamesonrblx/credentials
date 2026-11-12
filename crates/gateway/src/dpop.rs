//! DPoP (RFC 9449) proofs with an Ed25519 key.
//!
//! The proof binds the request method, URI, and access token. Verification
//! uses `ed25519-dalek`. The thumbprint is RFC 7638 over the OKP JWK members
//! in lexicographic order.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::b64::{b64url_decode, b64url_encode};
use crate::ApiError;

const PROOF_WINDOW_SECS: u64 = 60;
const LEEWAY_SECS: u64 = 30;

#[derive(Clone, Debug)]
pub struct DpopMaterial {
    pub jkt: String,
    pub jti: String,
}

pub struct DpopKey {
    signing: SigningKey,
    x_b64: String,
    pub jkt: String,
}

impl DpopKey {
    pub fn generate() -> Result<Self, ApiError> {
        let mut seed = [0u8; 32];
        credentials_crypto::random_bytes(&mut seed).map_err(|_| ApiError::KmsUnavailable)?;
        let signing = SigningKey::from_bytes(&seed);
        let x_b64 = b64url_encode(&signing.verifying_key().to_bytes());
        let jkt = thumbprint(&x_b64);
        Ok(Self {
            signing,
            x_b64,
            jkt,
        })
    }

    pub fn public_b64(&self) -> &str {
        &self.x_b64
    }

    pub fn proof(&self, htm: &str, htu: &str, access_token: &str, now: u64, jti: &str) -> String {
        let header = format!(
            r#"{{"alg":"EdDSA","jwk":{{"crv":"Ed25519","kty":"OKP","x":"{}"}},"typ":"dpop+jwt"}}"#,
            self.x_b64
        );
        let payload = serde_json::json!({
            "htm": htm,
            "htu": htu,
            "iat": now,
            "ath": access_token_hash(access_token),
            "jti": jti,
        });
        let payload_bytes = serde_json::to_vec(&payload).expect("dpop payload");
        let signing_input = format!(
            "{}.{}",
            b64url_encode(header.as_bytes()),
            b64url_encode(&payload_bytes)
        );
        let signature = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url_encode(&signature.to_bytes()))
    }
}

pub fn verify_dpop(
    proof: &str,
    access_token: &str,
    htm: &str,
    htu: &str,
    now: u64,
) -> Result<DpopMaterial, ApiError> {
    let mut parts = proof.split('.');
    let header_b64 = parts.next().ok_or(ApiError::Unauthenticated)?;
    let payload_b64 = parts.next().ok_or(ApiError::Unauthenticated)?;
    let sig_b64 = parts.next().ok_or(ApiError::Unauthenticated)?;
    if parts.next().is_some() {
        return Err(ApiError::Unauthenticated);
    }
    let header: serde_json::Value = serde_json::from_slice(&b64url_decode(header_b64)?)
        .map_err(|_| ApiError::Unauthenticated)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA")
        || header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt")
    {
        return Err(ApiError::Unauthenticated);
    }
    let x_b64 = header
        .pointer("/jwk/x")
        .and_then(|v| v.as_str())
        .ok_or(ApiError::Unauthenticated)?;
    if header.pointer("/jwk/kty").and_then(|v| v.as_str()) != Some("OKP")
        || header.pointer("/jwk/crv").and_then(|v| v.as_str()) != Some("Ed25519")
    {
        return Err(ApiError::Unauthenticated);
    }
    let verifying =
        VerifyingKey::from_bytes(&decode_public(x_b64)?).map_err(|_| ApiError::Unauthenticated)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = b64url_decode(sig_b64)?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Unauthenticated)?;
    verifying
        .verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_array))
        .map_err(|_| ApiError::Unauthenticated)?;

    let body: DpopBody = serde_json::from_slice(&b64url_decode(payload_b64)?)
        .map_err(|_| ApiError::Unauthenticated)?;
    if body.htm != htm || body.htu != htu || body.ath != access_token_hash(access_token) {
        return Err(ApiError::Unauthenticated);
    }
    if body.jti.is_empty() {
        return Err(ApiError::Unauthenticated);
    }
    let earliest = now.saturating_sub(PROOF_WINDOW_SECS + LEEWAY_SECS);
    let latest = now.saturating_add(LEEWAY_SECS);
    if body.iat < earliest || body.iat > latest {
        return Err(ApiError::Unauthenticated);
    }
    Ok(DpopMaterial {
        jkt: thumbprint(x_b64),
        jti: body.jti,
    })
}

pub fn thumbprint(x_b64: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    b64url_encode(&digest)
}

fn access_token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    b64url_encode(&digest)
}

fn decode_public(x_b64: &str) -> Result<[u8; 32], ApiError> {
    let bytes = b64url_decode(x_b64)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::Unauthenticated)
}

#[derive(Deserialize)]
struct DpopBody {
    htm: String,
    htu: String,
    iat: u64,
    ath: String,
    jti: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_vector() {
        let x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(thumbprint(x), "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0");
    }

    #[test]
    fn proof_round_trip_and_wrong_key() {
        let key = DpopKey::generate().unwrap();
        let token = "access-token-value";
        let proof = key.proof(
            "POST",
            "https://gw.example/v1/inject",
            token,
            1_000,
            "jti-1",
        );
        let material =
            verify_dpop(&proof, token, "POST", "https://gw.example/v1/inject", 1_000).unwrap();
        assert_eq!(material.jkt, key.jkt);
        assert!(verify_dpop(&proof, token, "GET", "https://gw.example/v1/inject", 1_000).is_err());
        assert!(verify_dpop(
            &proof,
            "other-token",
            "POST",
            "https://gw.example/v1/inject",
            1_000
        )
        .is_err());
    }
}
