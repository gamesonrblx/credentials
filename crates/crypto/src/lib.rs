//! Envelope encryption for Credentials.
//!
//! The byte layout follows `docs/ENCRYPTION.md`.
//! AES-256-GCM comes from the RustCrypto `aes-gcm` crate.
//! X-Wing comes from the RustCrypto `x-wing` crate.
//! This crate does not implement a cipher, a KEM, or a combiner.
//!
//! The dev root-key file holds raw keys.
//! `CREDENTIALS_ENV=production` rejects that provider.

#![forbid(unsafe_code)]

mod aad;
mod aead;
mod crd2;
mod envelope;
mod error;
mod hybrid;
mod kms;
mod random;
mod recovery;
#[cfg(test)]
mod xwing_kat;

pub use aad::{dek_aad, payload_aad, ALG_AES_256_GCM_V1, PURPOSE_DEK, PURPOSE_PAYLOAD};
pub use crd2::{
    open_e2e, seal_e2e, E2eSealed, E2E_DEK_WRAP_ALG, E2E_ENCAPSULATION_KEY_LEN,
    E2E_ENCAPSULATION_LEN,
};
pub use envelope::{
    open_secret, rewrap_dek, seal_secret, OpenSecret, SealedSecret, UnwrappedKek, VersionIds,
    DEFAULT_MAX_SECRET_BYTES, DEK_WRAP_ALG, HARD_MAX_SECRET_BYTES, PAYLOAD_ALG,
};
pub use error::CryptoError;
pub use hybrid::{
    generate_hybrid_keypair, unwrap_key, unwrap_key_with_aad, wrap_key, wrap_key_with_aad,
    HybridKeyPair, HybridWrapped,
};
pub use kms::{
    CountingProvider, DevFileRootKeys, DevPolicy, KekContext, MemoryRootKeys, RejectingRootKeys,
    RootKeyProvider, RootKeyState,
};
pub use random::random_bytes;
pub use recovery::{
    derive_kit_key, open_from_device, open_from_passkey, open_recovery_kit, seal_recovery_kit,
    seal_to_device, seal_to_passkey, KitParams, SymmetricWrap, KIT_MEMORY_KIB, KIT_PARALLELISM,
    KIT_TIME_COST,
};
