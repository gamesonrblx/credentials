//! CRD2, the end-to-end secret encoding.
//!
//! A random 32-byte data key encrypts the payload. X-Wing encapsulates to the
//! customer workspace key, and the 32-byte shared secret wraps that data key
//! with AES-256-GCM. The shared secret is not the data key. The tenant KEK is
//! not an input. Associated data uses the `CRD2` magic from `aad`.

use zeroize::Zeroizing;

use crate::aad::{dek_aad_e2e, payload_aad_e2e};
use crate::aead::{open, seal};
use crate::envelope::{VersionIds, HARD_MAX_SECRET_BYTES};
use crate::hybrid::{unwrap_key_with_aad, wrap_key_with_aad, HybridWrapped};
use crate::random::random_array;
use crate::CryptoError;
use uuid::Uuid;

pub const E2E_DEK_WRAP_ALG: &str = "crd2-xwing-aes-256-gcm-v1";
pub const E2E_ENCAPSULATION_LEN: usize = 1120;
pub const E2E_ENCAPSULATION_KEY_LEN: usize = 1216;

/// Ciphertext columns for one end-to-end secret version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E2eSealed {
    pub workspace_key_id: Uuid,
    pub payload_nonce: [u8; 12],
    pub payload_ciphertext: Vec<u8>,
    pub dek_wrap_nonce: [u8; 12],
    pub dek_wrapped: Vec<u8>,
    pub encapsulation: Vec<u8>,
    pub plaintext_len: usize,
}

/// Seal `plaintext` to a customer encapsulation key. The caller keeps the
/// decapsulation key. This function never sees a tenant KEK.
pub fn seal_e2e(
    encapsulation_key: &[u8],
    workspace_key_id: Uuid,
    ids: VersionIds,
    plaintext: &[u8],
    max_bytes: usize,
) -> Result<E2eSealed, CryptoError> {
    let max_bytes = max_bytes.min(HARD_MAX_SECRET_BYTES);
    if plaintext.is_empty() || plaintext.len() > max_bytes {
        return Err(CryptoError::SecretLength);
    }
    let dek = Zeroizing::new(random_array::<32>()?);
    let payload_nonce: [u8; 12] = random_array()?;
    let payload_aad = payload_aad_e2e(ids.workspace_id, ids.secret_id, ids.version_id);
    let payload_ciphertext = seal(&dek, &payload_nonce, plaintext, &payload_aad)?;
    let wrap_aad = dek_aad_e2e(
        ids.workspace_id,
        ids.secret_id,
        ids.version_id,
        workspace_key_id,
    );
    let wrapped = wrap_key_with_aad(encapsulation_key, &dek, &wrap_aad)?;
    if wrapped.encapsulation.len() != E2E_ENCAPSULATION_LEN {
        return Err(CryptoError::Hybrid);
    }
    Ok(E2eSealed {
        workspace_key_id,
        payload_nonce,
        payload_ciphertext,
        dek_wrap_nonce: wrapped.nonce,
        dek_wrapped: wrapped.ciphertext,
        encapsulation: wrapped.encapsulation,
        plaintext_len: plaintext.len(),
    })
}

/// Open a CRD2 row with the customer decapsulation key.
pub fn open_e2e(
    decapsulation_key: &[u8; 32],
    sealed: &E2eSealed,
    ids: VersionIds,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.encapsulation.len() != E2E_ENCAPSULATION_LEN {
        return Err(CryptoError::Hybrid);
    }
    let wrap_aad = dek_aad_e2e(
        ids.workspace_id,
        ids.secret_id,
        ids.version_id,
        sealed.workspace_key_id,
    );
    let wrapped = HybridWrapped {
        encapsulation: sealed.encapsulation.clone(),
        nonce: sealed.dek_wrap_nonce,
        ciphertext: sealed.dek_wrapped.clone(),
    };
    let dek = unwrap_key_with_aad(decapsulation_key, &wrapped, &wrap_aad)?;
    let payload_aad = payload_aad_e2e(ids.workspace_id, ids.secret_id, ids.version_id);
    let plaintext = open(
        &dek,
        &sealed.payload_nonce,
        &sealed.payload_ciphertext,
        &payload_aad,
    )?;
    if plaintext.len() != sealed.plaintext_len {
        return Err(CryptoError::Decrypt);
    }
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{open_secret, seal_secret, OpenSecret};
    use crate::hybrid::generate_hybrid_keypair;

    #[test]
    fn customer_key_opens_and_a_tenant_kek_does_not() {
        let pair = generate_hybrid_keypair().unwrap();
        let ids = VersionIds {
            workspace_id: Uuid::now_v7(),
            secret_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
        };
        let key_id = Uuid::now_v7();
        let sealed = seal_e2e(&pair.encapsulation_key, key_id, ids, b"sk-e2e", 1024).unwrap();
        assert_eq!(sealed.encapsulation.len(), E2E_ENCAPSULATION_LEN);
        let opened = open_e2e(pair.decapsulation_key(), &sealed, ids).unwrap();
        assert_eq!(opened.as_slice(), b"sk-e2e");

        let kek = Zeroizing::new(crate::random::random_array::<32>().unwrap());
        let kek_id = Uuid::now_v7();
        let gateway = seal_secret(&kek, kek_id, 1, ids, b"sk-e2e", 1024).unwrap();
        let err = open_secret(OpenSecret {
            kek: &kek,
            kek_id,
            kek_version: 1,
            ids,
            payload_alg: &gateway.payload_alg,
            dek_wrap_alg: E2E_DEK_WRAP_ALG,
            payload_nonce: &sealed.payload_nonce,
            payload_ciphertext: &sealed.payload_ciphertext,
            dek_wrap_nonce: &sealed.dek_wrap_nonce,
            dek_wrapped: &sealed.dek_wrapped,
        });
        assert!(err.is_err());
        assert_eq!(gateway.payload_alg, crate::PAYLOAD_ALG);
    }
}
