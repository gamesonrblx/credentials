//! WebAuthn registration and authentication.
//!
//! `webauthn-rs` checks the ceremony. The software authenticator keeps the
//! PRF key. The relying party stores the passkey and does not store the PRF
//! output.

use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn, WebauthnBuilder,
};

#[derive(Debug)]
pub struct WebauthnError;

pub struct Authenticator {
    signing: SigningKey,
    credential_id: Vec<u8>,
    prf_key: [u8; 32],
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
            credential_id: id.to_vec(),
            prf_key: prf,
        }
    }

    pub fn register(
        &self,
        options: &CreationChallengeResponse,
        origin: &str,
    ) -> RegisterPublicKeyCredential {
        let client_data = client_json("webauthn.create", &options.public_key.challenge, origin);
        let auth_data = self.auth_data(origin_rp(origin), true, 0);
        let attestation = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("fmt".into()),
                ciborium::Value::Text("none".into()),
            ),
            (
                ciborium::Value::Text("attStmt".into()),
                ciborium::Value::Map(Vec::new()),
            ),
            (
                ciborium::Value::Text("authData".into()),
                ciborium::Value::Bytes(auth_data),
            ),
        ]);
        let mut attestation_object = Vec::new();
        ciborium::into_writer(&attestation, &mut attestation_object).expect("cbor");
        RegisterPublicKeyCredential {
            id: b64(&self.credential_id),
            raw_id: self.credential_id.clone(),
            response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json: client_data,
                transports: None,
            },
            type_: "public-key".into(),
            extensions: webauthn_rs_proto::RegistrationExtensionsClientOutputs {
                appid: None,
                cred_props: None,
                hmac_secret: None,
                cred_protect: None,
                min_pin_length: None,
            },
        }
    }

    pub fn authenticate(
        &self,
        options: &RequestChallengeResponse,
        origin: &str,
        counter: u32,
    ) -> PublicKeyCredential {
        let client_data = client_json("webauthn.get", &options.public_key.challenge, origin);
        let auth_data = self.auth_data(origin_rp(origin), false, counter);
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = p256::ecdsa::signature::Signer::sign(&self.signing, &message);
        PublicKeyCredential {
            id: b64(&self.credential_id),
            raw_id: self.credential_id.clone(),
            response: webauthn_rs_proto::AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data,
                client_data_json: client_data,
                signature: signature.to_der().as_bytes().to_vec(),
                user_handle: None,
            },
            extensions: webauthn_rs_proto::AuthenticationExtensionsClientOutputs {
                appid: None,
                hmac_get_secret: None,
            },
            type_: "public-key".into(),
        }
    }

    /// PRF output for a salt. The relying party must not receive this.
    pub fn prf(&self, salt: &[u8]) -> [u8; 32] {
        crate::aws_kms::hmac_sha256(&self.prf_key, salt)
    }

    fn auth_data(&self, rp_id: &str, attestation: bool, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(if attestation { 0x45 } else { 0x05 });
        data.extend_from_slice(&counter.to_be_bytes());
        if attestation {
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&cose_key(&self.signing));
        }
        data
    }
}

pub fn relying_party(rp_id: &str, origin: &str) -> Result<Webauthn, WebauthnError> {
    let url = Url::parse(origin).map_err(|_| WebauthnError)?;
    WebauthnBuilder::new(rp_id, &url)
        .map_err(|_| WebauthnError)?
        .rp_name("Credentials")
        .build()
        .map_err(|_| WebauthnError)
}

pub fn register(
    auth: &Authenticator,
    party: &Webauthn,
    user: Uuid,
    origin: &str,
) -> Result<(Passkey, PasskeyRegistration), WebauthnError> {
    let (options, state) = party
        .start_passkey_registration(user, "ada", "Ada", None)
        .map_err(|_| WebauthnError)?;
    let credential = auth.register(&options, origin);
    let passkey = party
        .finish_passkey_registration(&credential, &state)
        .map_err(|_| WebauthnError)?;
    Ok((passkey, state))
}

pub fn authenticate(
    auth: &Authenticator,
    party: &Webauthn,
    passkey: &Passkey,
    origin: &str,
) -> Result<(), WebauthnError> {
    let (options, state) = party
        .start_passkey_authentication(std::slice::from_ref(passkey))
        .map_err(|_| WebauthnError)?;
    let assertion = auth.authenticate(&options, origin, 1);
    party
        .finish_passkey_authentication(&assertion, &state)
        .map(|_| ())
        .map_err(|_| WebauthnError)
}

pub fn stored_passkey_hides_prf(passkey: &Passkey, prf: &[u8]) -> bool {
    let stored = serde_json::to_string(passkey).unwrap_or_default();
    !stored.contains(&hex(prf))
}

fn cose_key(signing: &SigningKey) -> Vec<u8> {
    let point = signing.verifying_key().to_sec1_bytes();
    let x = point[1..33].to_vec();
    let y = point[33..65].to_vec();
    let key = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer((-7).into()),
        ),
        (
            ciborium::Value::Integer((-1).into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-2).into()),
            ciborium::Value::Bytes(x),
        ),
        (
            ciborium::Value::Integer((-3).into()),
            ciborium::Value::Bytes(y),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&key, &mut out).expect("cbor");
    out
}

fn client_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": b64(challenge),
        "origin": origin,
    }))
    .expect("json")
}

fn origin_rp(origin: &str) -> &str {
    origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(origin)
}

fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
