//! Envelope encryption for Credentials.
//!
//! The wire format follows `docs/ENCRYPTION.md`. AES-256-GCM comes from the
//! RustCrypto `aes-gcm` crate. Hybrid key transport uses RustCrypto `x-wing`
//! (X25519 + ML-KEM-768). This crate does not implement a cipher, a KEM, or a
//! combiner.
//!
//! The dev and in-memory root-key providers exist so the gateway can run
//! without a cloud KMS. They are refused when `CREDENTIALS_ENV=production`.
//! They are not a production key store: the dev file holds raw root keys.

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
pub use crd2::{open_e2e, seal_e2e, E2eSealed, E2E_DEK_WRAP_ALG, E2E_ENCAPSULATION_LEN};
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
    CountingProvider, DevFileRootKeys, DevPolicy, KekContext, MemoryRootKeys, RootKeyProvider,
    RootKeyState,
};
pub use random::random_bytes;
pub use recovery::{
    derive_kit_key, open_from_device, open_from_passkey, open_recovery_kit, seal_recovery_kit,
    seal_to_device, seal_to_passkey, KitParams, SymmetricWrap, KIT_MEMORY_KIB, KIT_PARALLELISM,
    KIT_TIME_COST,
};
