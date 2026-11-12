//! WebAuthn registration and authentication.
//!
//! `webauthn-rs` checks the ceremony. The relying party stores the passkey
//! and does not store the PRF output. The gateway does not call this module
//! yet.
//!
//! `Authenticator` is a software authenticator that keeps the PRF key. It
//! exists for tests and is only built with `cfg(test)` or the `test-util`
//! feature.

#[cfg(any(test, feature = "test-util"))]
use p256::ecdsa::{Signature, SigningKey};
#[cfg(any(test, feature = "test-util"))]
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

#[derive(Debug, thiserror::Error)]
#[error("webauthn ceremony failed")]
pub struct WebauthnError;

/// Software authenticator for tests. Its keys are zeroized on drop.
#[cfg(any(test, feature = "test-util"))]
pub struct Authenticator {
    signing: SigningKey,
    credential_id: Vec<u8>,
    prf_key: zeroize::Zeroizing<[u8; 32]>,
}

#[cfg(any(test, feature = "test-util"))]
impl Authenticator {
    pub fn generate() -> Result<Self, WebauthnError> {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        let mut id = [0u8; 16];
        let mut prf = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut_slice()).map_err(|_| WebauthnError)?;
        getrandom::fill(&mut id).map_err(|_| WebauthnError)?;
        getrandom::fill(prf.as_mut_slice()).map_err(|_| WebauthnError)?;
        Ok(Self {
            signing: SigningKey::from_bytes((&*seed).into()).map_err(|_| WebauthnError)?,
            credential_id: id.to_vec(),
            prf_key: prf,
        })
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
        ciborium::into_writer(&attestation, &mut attestation_object).expect("cbor to a Vec");
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
        crate::aws_kms::hmac_sha256(self.prf_key.as_slice(), salt)
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

/// Start passkey registration for a user. The caller keeps the returned
/// state server side until the browser answers.
pub fn start_registration(
    party: &Webauthn,
    user_id: Uuid,
    user_name: &str,
    display_name: &str,
) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
    if user_name.trim().is_empty() || display_name.trim().is_empty() {
        return Err(WebauthnError);
    }
    party
        .start_passkey_registration(user_id, user_name, display_name, None)
        .map_err(|_| WebauthnError)
}

/// Check the browser's registration answer and return the passkey to store.
pub fn finish_registration(
    party: &Webauthn,
    credential: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
) -> Result<Passkey, WebauthnError> {
    party
        .finish_passkey_registration(credential, state)
        .map_err(|_| WebauthnError)
}

/// Start authentication against the user's stored passkeys.
pub fn start_authentication(
    party: &Webauthn,
    passkeys: &[Passkey],
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
    party
        .start_passkey_authentication(passkeys)
        .map_err(|_| WebauthnError)
}

/// Check the browser's assertion against the saved authentication state.
pub fn finish_authentication(
    party: &Webauthn,
    credential: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> Result<(), WebauthnError> {
    party
        .finish_passkey_authentication(credential, state)
        .map(|_| ())
        .map_err(|_| WebauthnError)
}

/// Register `auth` for a user in one step. Test helper.
#[cfg(any(test, feature = "test-util"))]
pub fn register(
    auth: &Authenticator,
    party: &Webauthn,
    user_id: Uuid,
    user_name: &str,
    display_name: &str,
    origin: &str,
) -> Result<(Passkey, PasskeyRegistration), WebauthnError> {
    let (options, state) = start_registration(party, user_id, user_name, display_name)?;
    let credential = auth.register(&options, origin);
    let passkey = finish_registration(party, &credential, &state)?;
    Ok((passkey, state))
}

/// Authenticate `auth` against a stored passkey in one step. Test helper.
#[cfg(any(test, feature = "test-util"))]
pub fn authenticate(
    auth: &Authenticator,
    party: &Webauthn,
    passkey: &Passkey,
    origin: &str,
) -> Result<(), WebauthnError> {
    let (options, state) = start_authentication(party, std::slice::from_ref(passkey))?;
    let assertion = auth.authenticate(&options, origin, 1);
    finish_authentication(party, &assertion, &state)
}

#[cfg(any(test, feature = "test-util"))]
pub fn stored_passkey_hides_prf(passkey: &Passkey, prf: &[u8]) -> bool {
    let stored = serde_json::to_string(passkey).unwrap_or_default();
    !stored.contains(&hex(prf))
}

#[cfg(any(test, feature = "test-util"))]
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

#[cfg(any(test, feature = "test-util"))]
fn client_json(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": kind,
        "challenge": b64(challenge),
        "origin": origin,
    }))
    .expect("json")
}

#[cfg(any(test, feature = "test-util"))]
fn origin_rp(origin: &str) -> &str {
    origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(origin)
}

#[cfg(any(test, feature = "test-util"))]
fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

#[cfg(any(test, feature = "test-util"))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
