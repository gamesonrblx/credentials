//! WebAuthn registration and authentication with a software authenticator.
//!
//! The PRF output stays in the authenticator. The relying party stores the
//! public key, the credential id, and the salt. It does not store the PRF
//! output.

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct WebauthnError;

pub struct Authenticator {
    signing: SigningKey,
    credential_id: [u8; 16],
    prf_key: [u8; 32],
}

pub struct RelyingParty {
    pub origin: String,
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub salt: [u8; 32],
}

pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub client_data: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Authenticator {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        let mut id = [0u8; 16];
        let mut prf = [0u8; 32];
        getrandom::fill(&mut seed).expect("os random");
        getrandom::fill(&mut id).expect("os random");
        getrandom::fill(&mut prf).expect("os random");
        Self {
            signing: SigningKey::from_bytes((&seed).into()).expect("p256"),
            credential_id: id,
            prf_key: prf,
        }
    }

    pub fn register(&self, challenge: &[u8], rp_id: &str, origin: &str) -> Registration {
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": b64(challenge),
            "origin": origin,
        });
        let client_bytes = serde_json::to_vec(&client_data).expect("json");
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x41);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        let public = self.signing.verifying_key().to_sec1_bytes().to_vec();
        auth_data.extend_from_slice(&(public.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&public);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_bytes));
        let signature: Signature = p256::ecdsa::signature::Signer::sign(&self.signing, &signed);
        Registration {
            credential_id: self.credential_id.to_vec(),
            public_key: public,
            client_data: client_bytes,
            auth_data,
            signature: signature.to_bytes().to_vec(),
        }
    }

    pub fn authenticate(&self, challenge: &[u8], rp_id: &str, origin: &str) -> Registration {
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": b64(challenge),
            "origin": origin,
        });
        let client_bytes = serde_json::to_vec(&client_data).expect("json");
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x01);
        auth_data.extend_from_slice(&1u32.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_bytes));
        let signature: Signature = p256::ecdsa::signature::Signer::sign(&self.signing, &signed);
        Registration {
            credential_id: self.credential_id.to_vec(),
            public_key: self.signing.verifying_key().to_sec1_bytes().to_vec(),
            client_data: client_bytes,
            auth_data,
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// PRF output for a salt. The relying party must not receive this.
    pub fn prf(&self, salt: &[u8]) -> [u8; 32] {
        crate::aws_kms::hmac_sha256(&self.prf_key, salt)
    }
}

pub fn register(
    auth: &Authenticator,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
) -> Result<RelyingParty, WebauthnError> {
    let reg = auth.register(challenge, rp_id, origin);
    verify_client(&reg.client_data, "webauthn.create", challenge, origin)?;
    verify_signature(
        &reg.public_key,
        &reg.auth_data,
        &reg.client_data,
        &reg.signature,
    )?;
    if &reg.auth_data[..32] != Sha256::digest(rp_id.as_bytes()).as_slice() {
        return Err(WebauthnError);
    }
    Ok(RelyingParty {
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
        credential_id: reg.credential_id,
        public_key: reg.public_key,
        salt: *b"credentials-prf-salt-32-bytes!!!",
    })
}

pub fn authenticate(
    party: &RelyingParty,
    auth: &Authenticator,
    challenge: &[u8],
) -> Result<(), WebauthnError> {
    let assertion = auth.authenticate(challenge, &party.rp_id, &party.origin);
    if assertion.credential_id != party.credential_id {
        return Err(WebauthnError);
    }
    verify_client(
        &assertion.client_data,
        "webauthn.get",
        challenge,
        &party.origin,
    )?;
    verify_signature(
        &party.public_key,
        &assertion.auth_data,
        &assertion.client_data,
        &assertion.signature,
    )
}

fn verify_client(
    bytes: &[u8],
    kind: &str,
    challenge: &[u8],
    origin: &str,
) -> Result<(), WebauthnError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| WebauthnError)?;
    if value.get("type").and_then(|v| v.as_str()) != Some(kind) {
        return Err(WebauthnError);
    }
    if value.get("origin").and_then(|v| v.as_str()) != Some(origin) {
        return Err(WebauthnError);
    }
    if value.get("challenge").and_then(|v| v.as_str()) != Some(b64(challenge).as_str()) {
        return Err(WebauthnError);
    }
    Ok(())
}

fn verify_signature(
    public: &[u8],
    auth_data: &[u8],
    client_data: &[u8],
    signature: &[u8],
) -> Result<(), WebauthnError> {
    let key = VerifyingKey::from_sec1_bytes(public).map_err(|_| WebauthnError)?;
    let sig = Signature::from_slice(signature).map_err(|_| WebauthnError)?;
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data));
    p256::ecdsa::signature::Verifier::verify(&key, &message, &sig).map_err(|_| WebauthnError)
}

fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}
