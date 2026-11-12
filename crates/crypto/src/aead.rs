//! AES-256-GCM via the RustCrypto `aes-gcm` crate.
//!
//! The ciphertext is the seal output, which is ciphertext followed by the
//! 16-byte tag. The nonce is stored beside it. `open` returns a buffer that is
//! wiped on drop, so an early return cannot leave key bytes or plaintext behind.

use aes_gcm::{
    aead::{
        array::Array,
        consts::{U12, U32},
        Aead, KeyInit, Payload,
    },
    Aes256Gcm,
};

use zeroize::Zeroizing;

use crate::CryptoError;

pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(&Array::<u8, U32>::from(*key));
    let nonce = Array::<u8, U12>::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::Decrypt)?;
    let cipher = Aes256Gcm::new(&Array::<u8, U32>::from(*key));
    let nonce = Array::<u8, U12>::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}
