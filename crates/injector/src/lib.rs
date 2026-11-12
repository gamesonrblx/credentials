//! Open a ciphertext grant with a customer-held decapsulation key.
//!
//! The control plane never links this crate. A grant is the JSON object
//! `POST /v1/inject` returns for `wrap_mode = e2e`. This process does not
//! accept a tenant KEK.

use base64::Engine;
use credentials_crypto::{open_e2e, E2eSealed, VersionIds};
use uuid::Uuid;

#[derive(Debug)]
pub enum InjectorError {
    Grant,
    Open,
}

pub fn open_grant(decapsulation_key: &[u8; 32], grant: &[u8]) -> Result<Vec<u8>, InjectorError> {
    let value: serde_json::Value =
        serde_json::from_slice(grant).map_err(|_| InjectorError::Grant)?;
    if value.get("wrap_mode").and_then(|v| v.as_str()) != Some("e2e") {
        return Err(InjectorError::Grant);
    }
    let ids = VersionIds {
        workspace_id: uuid_field(&value, "workspace_id")?,
        secret_id: uuid_field(&value, "secret_id")?,
        version_id: uuid_field(&value, "version_id")?,
    };
    let sealed = E2eSealed {
        workspace_key_id: uuid_field(&value, "workspace_key_id")?,
        payload_nonce: nonce(&value, "payload_nonce")?,
        payload_ciphertext: b64_field(&value, "payload_ciphertext")?,
        dek_wrap_nonce: nonce(&value, "dek_wrap_nonce")?,
        dek_wrapped: b64_field(&value, "dek_wrapped")?,
        encapsulation: b64_field(&value, "e2e_encapsulation")?,
        plaintext_len: value
            .get("plaintext_len")
            .and_then(|v| v.as_u64())
            .ok_or(InjectorError::Grant)? as usize,
    };
    let opened = open_e2e(decapsulation_key, &sealed, ids).map_err(|_| InjectorError::Open)?;
    Ok(opened.to_vec())
}

fn uuid_field(value: &serde_json::Value, name: &str) -> Result<Uuid, InjectorError> {
    let text = value
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or(InjectorError::Grant)?;
    Uuid::parse_str(text).map_err(|_| InjectorError::Grant)
}

fn b64_field(value: &serde_json::Value, name: &str) -> Result<Vec<u8>, InjectorError> {
    let text = value
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or(InjectorError::Grant)?;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| InjectorError::Grant)
}

fn nonce(value: &serde_json::Value, name: &str) -> Result<[u8; 12], InjectorError> {
    let bytes = b64_field(value, name)?;
    bytes.try_into().map_err(|_| InjectorError::Grant)
}

#[cfg(test)]
mod tests {
    use super::open_grant;
    use credentials_crypto::{generate_hybrid_keypair, seal_e2e, VersionIds};
    use uuid::Uuid;

    #[test]
    fn a_grant_opens_only_with_the_customer_key() {
        let pair = generate_hybrid_keypair().unwrap();
        let ids = VersionIds {
            workspace_id: Uuid::now_v7(),
            secret_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
        };
        let key_id = Uuid::now_v7();
        let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-injector", 1024).unwrap();
        let grant = serde_json::json!({
            "wrap_mode": "e2e",
            "workspace_id": ids.workspace_id,
            "secret_id": ids.secret_id,
            "version_id": ids.version_id,
            "workspace_key_id": key_id,
            "payload_nonce": b64(&sealed.payload_nonce),
            "payload_ciphertext": b64(&sealed.payload_ciphertext),
            "dek_wrap_nonce": b64(&sealed.dek_wrap_nonce),
            "dek_wrapped": b64(&sealed.dek_wrapped),
            "e2e_encapsulation": b64(&sealed.encapsulation),
            "plaintext_len": sealed.plaintext_len,
        });
        let bytes = serde_json::to_vec(&grant).unwrap();
        let opened = open_grant(pair.decapsulation_key(), &bytes).unwrap();
        assert_eq!(opened, b"sk-injector");
        assert!(open_grant(&[9u8; 32], &bytes).is_err());
    }

    fn b64(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }
}
