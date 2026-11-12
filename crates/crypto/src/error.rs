use thiserror::Error;

/// Failures from the crypto crate. Callers that face an agent map these onto
/// a generic decrypt or KMS error. They do not include key bytes or plaintext.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("the system random source failed")]
    Random,
    #[error("decryption failed")]
    Decrypt,
    #[error("the algorithm label is not supported")]
    Algorithm,
    #[error("the secret length is outside the allowed range")]
    SecretLength,
    #[error("key material has the wrong length")]
    KeyLength,
    #[error("a dev root-key provider cannot run when CREDENTIALS_ENV=production")]
    DevProviderInProduction,
    #[error("CREDENTIALS_ENV must be production, prod, development, dev, or test")]
    UnknownEnvironment,
    #[error("the tenant root key is not available")]
    RootKeyUnavailable,
    #[error("the dev key file could not be read or written")]
    Io,
    #[error("the dev key file is corrupt")]
    CorruptStore,
    #[error("hybrid key transport failed")]
    Hybrid,
    #[error("key derivation failed")]
    Kdf,
}
