//! Seal and open one secret version, and re-wrap its data key.

use zeroize::Zeroizing;

use crate::aad::{dek_aad, payload_aad};
use crate::aead::{open, seal};
use crate::random::random_array;
use crate::CryptoError;
use uuid::Uuid;

pub const PAYLOAD_ALG: &str = "aes-256-gcm-v1";
pub const DEK_WRAP_ALG: &str = "aes-256-gcm-v1";
pub const DEFAULT_MAX_SECRET_BYTES: usize = 65_536;
pub const HARD_MAX_SECRET_BYTES: usize = 1_048_576;

/// Immutable ids bound into associated data. The version id is the row UUID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionIds {
    pub workspace_id: Uuid,
    pub secret_id: Uuid,
    pub version_id: Uuid,
}

/// Stored columns for one secret version. No plaintext and no data key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSecret {
    pub payload_alg: String,
    pub payload_nonce: [u8; 12],
    pub payload_ciphertext: Vec<u8>,
    pub dek_wrap_alg: String,
    pub dek_wrap_nonce: [u8; 12],
    pub dek_wrapped: Vec<u8>,
    pub plaintext_len: usize,
}

/// Borrowed view used to open a row, including algorithm labels.
pub struct OpenSecret<'a> {
    pub kek: &'a [u8; 32],
    pub kek_id: Uuid,
    pub kek_version: u32,
    pub ids: VersionIds,
    pub payload_alg: &'a str,
    pub dek_wrap_alg: &'a str,
    pub payload_nonce: &'a [u8],
    pub payload_ciphertext: &'a [u8],
    pub dek_wrap_nonce: &'a [u8],
    pub dek_wrapped: &'a [u8],
}

/// Encrypt `plaintext` under a fresh data key and wrap that key under `kek`.
pub fn seal_secret(
    kek: &[u8; 32],
    kek_id: Uuid,
    kek_version: u32,
    ids: VersionIds,
    plaintext: &[u8],
    max_bytes: usize,
) -> Result<SealedSecret, CryptoError> {
    let max_bytes = max_bytes.min(HARD_MAX_SECRET_BYTES);
    if plaintext.is_empty() || plaintext.len() > max_bytes {
        return Err(CryptoError::SecretLength);
    }

    let dek = Zeroizing::new(random_array::<32>()?);
    let payload_nonce: [u8; 12] = random_array()?;
    let payload_aad = payload_aad(ids.workspace_id, ids.secret_id, ids.version_id);
    let payload_ciphertext = seal(&dek, &payload_nonce, plaintext, &payload_aad)?;

    let dek_wrap_nonce: [u8; 12] = random_array()?;
    let wrap_aad = dek_aad(
        ids.workspace_id,
        ids.secret_id,
        ids.version_id,
        kek_id,
        kek_version,
    );
    let dek_wrapped = seal(kek, &dek_wrap_nonce, dek.as_slice(), &wrap_aad)?;

    Ok(SealedSecret {
        payload_alg: PAYLOAD_ALG.to_owned(),
        payload_nonce,
        payload_ciphertext,
        dek_wrap_alg: DEK_WRAP_ALG.to_owned(),
        dek_wrap_nonce,
        dek_wrapped,
        plaintext_len: plaintext.len(),
    })
}

/// Unwrap the data key and open the payload. Wipes the data key before returning.
pub fn open_secret(req: OpenSecret<'_>) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if req.payload_alg != PAYLOAD_ALG || req.dek_wrap_alg != DEK_WRAP_ALG {
        return Err(CryptoError::Algorithm);
    }
    let wrap_aad = dek_aad(
        req.ids.workspace_id,
        req.ids.secret_id,
        req.ids.version_id,
        req.kek_id,
        req.kek_version,
    );
    let mut dek_bytes = open(req.kek, req.dek_wrap_nonce, req.dek_wrapped, &wrap_aad)?;
    if dek_bytes.len() != 32 {
        dek_bytes.fill(0);
        return Err(CryptoError::KeyLength);
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&dek_bytes);
    dek_bytes.fill(0);

    let payload_aad = payload_aad(req.ids.workspace_id, req.ids.secret_id, req.ids.version_id);
    let plaintext = open(
        &dek,
        req.payload_nonce,
        req.payload_ciphertext,
        &payload_aad,
    )?;
    Ok(Zeroizing::new(plaintext))
}

/// A KEK already unwrapped in memory, plus the ids bound into the wrap.
pub struct UnwrappedKek<'a> {
    pub key: &'a [u8; 32],
    pub id: Uuid,
    pub version: u32,
}

/// Wrap the same data key under a new KEK. Payload bytes stay as they are.
pub fn rewrap_dek(
    old: UnwrappedKek<'_>,
    new: UnwrappedKek<'_>,
    ids: VersionIds,
    sealed: &SealedSecret,
) -> Result<SealedSecret, CryptoError> {
    if sealed.dek_wrap_alg != DEK_WRAP_ALG {
        return Err(CryptoError::Algorithm);
    }
    let wrap_aad = dek_aad(
        ids.workspace_id,
        ids.secret_id,
        ids.version_id,
        old.id,
        old.version,
    );
    let mut dek_bytes = open(
        old.key,
        &sealed.dek_wrap_nonce,
        &sealed.dek_wrapped,
        &wrap_aad,
    )?;
    if dek_bytes.len() != 32 {
        dek_bytes.fill(0);
        return Err(CryptoError::KeyLength);
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&dek_bytes);
    dek_bytes.fill(0);

    let dek_wrap_nonce: [u8; 12] = random_array()?;
    let new_aad = dek_aad(
        ids.workspace_id,
        ids.secret_id,
        ids.version_id,
        new.id,
        new.version,
    );
    let dek_wrapped = seal(new.key, &dek_wrap_nonce, dek.as_slice(), &new_aad)?;

    Ok(SealedSecret {
        payload_alg: sealed.payload_alg.clone(),
        payload_nonce: sealed.payload_nonce,
        payload_ciphertext: sealed.payload_ciphertext.clone(),
        dek_wrap_alg: sealed.dek_wrap_alg.clone(),
        dek_wrap_nonce,
        dek_wrapped,
        plaintext_len: sealed.plaintext_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> VersionIds {
        VersionIds {
            workspace_id: Uuid::now_v7(),
            secret_id: Uuid::now_v7(),
            version_id: Uuid::now_v7(),
        }
    }

    fn kek() -> [u8; 32] {
        random_array().unwrap()
    }

    #[test]
    fn round_trip() {
        let kek = kek();
        let kek_id = Uuid::now_v7();
        let ids = ids();
        let sealed = seal_secret(&kek, kek_id, 1, ids, b"sk-live-value", 1024).unwrap();
        let opened = open_secret(OpenSecret {
            kek: &kek,
            kek_id,
            kek_version: 1,
            ids,
            payload_alg: &sealed.payload_alg,
            dek_wrap_alg: &sealed.dek_wrap_alg,
            payload_nonce: &sealed.payload_nonce,
            payload_ciphertext: &sealed.payload_ciphertext,
            dek_wrap_nonce: &sealed.dek_wrap_nonce,
            dek_wrapped: &sealed.dek_wrapped,
        })
        .unwrap();
        assert_eq!(opened.as_slice(), b"sk-live-value");
    }

    #[test]
    fn bit_flip_fails() {
        let kek = kek();
        let kek_id = Uuid::now_v7();
        let ids = ids();
        let mut sealed = seal_secret(&kek, kek_id, 1, ids, b"abcdef", 1024).unwrap();
        sealed.payload_ciphertext[0] ^= 0x01;
        let err = open_secret(view(&kek, kek_id, 1, ids, &sealed)).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn swapped_ciphertext_and_workspace_fail() {
        let kek = kek();
        let kek_id = Uuid::now_v7();
        let a = ids();
        let b = ids();
        let sealed_a = seal_secret(&kek, kek_id, 1, a, b"alpha-secret", 1024).unwrap();
        let sealed_b = seal_secret(&kek, kek_id, 1, b, b"beta-secret", 1024).unwrap();

        let mut swapped = sealed_a.clone();
        swapped.payload_ciphertext = sealed_b.payload_ciphertext.clone();
        assert!(open_secret(view(&kek, kek_id, 1, a, &swapped)).is_err());

        let mut other_workspace = sealed_a.clone();
        let mut wrong = a;
        wrong.workspace_id = b.workspace_id;
        assert!(open_secret(view(&kek, kek_id, 1, wrong, &other_workspace)).is_err());

        other_workspace.dek_wrapped = sealed_b.dek_wrapped.clone();
        other_workspace.dek_wrap_nonce = sealed_b.dek_wrap_nonce;
        assert!(open_secret(view(&kek, kek_id, 1, a, &other_workspace)).is_err());
    }

    #[test]
    fn rewrap_keeps_payload_bytes() {
        let old = kek();
        let new = kek();
        let old_id = Uuid::now_v7();
        let new_id = Uuid::now_v7();
        let ids = ids();
        let sealed = seal_secret(&old, old_id, 1, ids, b"rotate-me", 1024).unwrap();
        let rewrapped = rewrap_dek(
            UnwrappedKek {
                key: &old,
                id: old_id,
                version: 1,
            },
            UnwrappedKek {
                key: &new,
                id: new_id,
                version: 2,
            },
            ids,
            &sealed,
        )
        .unwrap();
        assert_eq!(rewrapped.payload_ciphertext, sealed.payload_ciphertext);
        assert_eq!(rewrapped.payload_nonce, sealed.payload_nonce);
        assert_ne!(rewrapped.dek_wrapped, sealed.dek_wrapped);
        let opened = open_secret(view(&new, new_id, 2, ids, &rewrapped)).unwrap();
        assert_eq!(opened.as_slice(), b"rotate-me");
        assert!(open_secret(view(&old, old_id, 1, ids, &rewrapped)).is_err());
    }

    #[test]
    fn rejects_empty_unknown_alg_and_bad_nonce() {
        let kek = kek();
        let kek_id = Uuid::now_v7();
        let ids = ids();
        assert!(matches!(
            seal_secret(&kek, kek_id, 1, ids, b"", 1024),
            Err(CryptoError::SecretLength)
        ));
        let sealed = seal_secret(&kek, kek_id, 1, ids, b"ok", 1024).unwrap();
        let mut req = view(&kek, kek_id, 1, ids, &sealed);
        req.payload_alg = "aes-128-gcm";
        assert!(matches!(open_secret(req), Err(CryptoError::Algorithm)));
        let mut req = view(&kek, kek_id, 1, ids, &sealed);
        req.payload_nonce = &sealed.payload_nonce[..11];
        assert!(open_secret(req).is_err());
    }

    fn view<'a>(
        kek: &'a [u8; 32],
        kek_id: Uuid,
        kek_version: u32,
        ids: VersionIds,
        sealed: &'a SealedSecret,
    ) -> OpenSecret<'a> {
        OpenSecret {
            kek,
            kek_id,
            kek_version,
            ids,
            payload_alg: &sealed.payload_alg,
            dek_wrap_alg: &sealed.dek_wrap_alg,
            payload_nonce: &sealed.payload_nonce,
            payload_ciphertext: &sealed.payload_ciphertext,
            dek_wrap_nonce: &sealed.dek_wrap_nonce,
            dek_wrapped: &sealed.dek_wrapped,
        }
    }
}
