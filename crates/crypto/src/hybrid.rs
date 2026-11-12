//! Hybrid key transport.
//!
//! X25519 + ML-KEM-768 via the RustCrypto `x-wing` crate (published 0.1.1).
//! That crate's combiner label is the six-byte X-Wing label from
//! draft-connolly-cfrg-xwing-kem (`5c2e2f2f5e5c`). The crate README still says
//! the code tracks draft 06; the label in 0.1.1 matches the draft-11 combiner.
//! This module calls the crate. It does not restate the combiner.
//!
//! The gateway-decrypts path does not use this. It is the application-level
//! wrap for a later hop that must send a 32-byte key to a peer: X-Wing
//! establishes a 32-byte shared secret, and that secret is the AES-256-GCM
//! key around the transported key.

use x_wing::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use x_wing::{DecapsulationKey, EncapsulationKey, XWingKem};
use zeroize::Zeroizing;

use crate::aead::{open, seal};
use crate::random::random_array;
use crate::CryptoError;

/// A client-side hybrid keypair. The decapsulation key stays with the caller.
pub struct HybridKeyPair {
    pub encapsulation_key: Vec<u8>,
    decapsulation_key: Zeroizing<[u8; 32]>,
}

impl HybridKeyPair {
    pub fn decapsulation_key(&self) -> &[u8; 32] {
        &self.decapsulation_key
    }
}

/// An X-Wing encapsulation plus an AES-256-GCM wrap of a 32-byte key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridWrapped {
    pub encapsulation: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn generate_hybrid_keypair() -> Result<HybridKeyPair, CryptoError> {
    let (sk, pk) = XWingKem::generate_keypair();
    let encapsulation_key = pk.to_bytes().as_slice().to_vec();
    let decapsulation_key = Zeroizing::new(*sk.as_bytes());
    Ok(HybridKeyPair {
        encapsulation_key,
        decapsulation_key,
    })
}

pub const HYBRID_WRAP_AAD: &[u8] = b"credentials.hybrid.wrap.v1";

pub fn wrap_key(encapsulation_key: &[u8], key: &[u8; 32]) -> Result<HybridWrapped, CryptoError> {
    wrap_key_with_aad(encapsulation_key, key, HYBRID_WRAP_AAD)
}

pub fn wrap_key_with_aad(
    encapsulation_key: &[u8],
    key: &[u8; 32],
    aad: &[u8],
) -> Result<HybridWrapped, CryptoError> {
    let pk = EncapsulationKey::try_from(encapsulation_key).map_err(|_| CryptoError::Hybrid)?;
    let (ct, shared) = pk.encapsulate();
    let shared_bytes = shared_key_bytes(&shared)?;
    let nonce: [u8; 12] = random_array()?;
    let ciphertext = seal(&shared_bytes, &nonce, key, aad)?;
    Ok(HybridWrapped {
        encapsulation: ct.as_slice().to_vec(),
        nonce,
        ciphertext,
    })
}

pub fn unwrap_key(
    decapsulation_key: &[u8; 32],
    wrapped: &HybridWrapped,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    unwrap_key_with_aad(decapsulation_key, wrapped, HYBRID_WRAP_AAD)
}

pub fn unwrap_key_with_aad(
    decapsulation_key: &[u8; 32],
    wrapped: &HybridWrapped,
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let sk = DecapsulationKey::from(*decapsulation_key);
    let shared = sk
        .decapsulate_slice(&wrapped.encapsulation)
        .map_err(|_| CryptoError::Hybrid)?;
    let shared_bytes = shared_key_bytes(&shared)?;
    let plain = open(&shared_bytes, &wrapped.nonce, &wrapped.ciphertext, aad)?;
    if plain.len() != 32 {
        return Err(CryptoError::KeyLength);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plain);
    Ok(out)
}

fn shared_key_bytes(shared: &x_wing::SharedKey) -> Result<[u8; 32], CryptoError> {
    let slice = shared.as_slice();
    let array: [u8; 32] = slice.try_into().map_err(|_| CryptoError::Hybrid)?;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_wrap_round_trip_and_tamper() {
        let pair = generate_hybrid_keypair().unwrap();
        assert_eq!(pair.encapsulation_key.len(), 1216);
        let key = random_array::<32>().unwrap();
        let wrapped = wrap_key(&pair.encapsulation_key, &key).unwrap();
        assert_eq!(wrapped.encapsulation.len(), 1120);
        let opened = unwrap_key(pair.decapsulation_key(), &wrapped).unwrap();
        assert_eq!(opened.as_slice(), &key);

        let mut tampered = wrapped.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert!(unwrap_key(pair.decapsulation_key(), &tampered).is_err());
    }
}
