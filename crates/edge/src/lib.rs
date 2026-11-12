//! Adapters that sit beside the control plane.
//!
//! The hosted control plane still uses `RejectingRootKeys`. These types
//! run in the customer injector, a dev process, or an attested enclave.
//! None of them adds an operator recovery recipient.
//!
//! What is wired into the gateway today:
//!
//! - `oidc`: wired. The gateway's dashboard login calls
//!   `start_browser_login` and `finish_browser_login`.
//! - `aws_kms`: not wired. An AWS KMS `RootKeyProvider` and SigV4 signer,
//!   exercised only by unit tests and the LocalStack integration test.
//! - `vault`: not wired. A Vault Transit `RootKeyProvider`, exercised only by
//!   the Vault integration test.
//! - `s3lock`: not wired. An S3 Object Lock writer, exercised only by the
//!   MinIO integration test.
//! - `importers`: not wired. Readers for Infisical, Doppler, 1Password and
//!   Vault KV, exercised only by fixture and integration tests.
//! - `webauthn`: not wired. Passkey ceremonies, exercised only by unit tests
//!   with a software authenticator.
//! - `nitro`: not wired. Nitro attestation verification, exercised only by
//!   unit tests with a test certificate chain.
//!
//! The `test-util` feature adds test helpers: the software authenticator,
//! the IdP password-form login, and the Nitro document builder.

pub mod aws_kms;
pub mod importers;
mod net;
pub mod nitro;
pub mod oidc;
pub mod s3lock;
pub mod vault;
pub mod webauthn;

pub use aws_kms::{
    amz_now, authorization, authorization_with_token, kms_key_policy, s3_authorization, AwsKms,
    KmsError,
};
pub use importers::{read_doppler, read_infisical, read_onepassword, read_vault_kv, SourceSecret};
#[cfg(any(test, feature = "test-util"))]
pub use nitro::{seal_document, SealFields};
pub use nitro::{sha256_der, verify_attestation, Attestation, AttestationPolicy, NitroError};
#[cfg(any(test, feature = "test-util"))]
pub use oidc::login_with_password;
pub use oidc::{
    authorize_url, exchange_code, finish_browser_login, start_browser_login, BrowserLogin,
    CodeChallenge, HumanLogin, OidcClient, OidcError,
};
pub use s3lock::{put_locked, LockError, LockedObject};
pub use vault::VaultTransit;
#[cfg(any(test, feature = "test-util"))]
pub use webauthn::{authenticate, register, Authenticator};
pub use webauthn::{
    finish_authentication, finish_registration, relying_party, start_authentication,
    start_registration, WebauthnError,
};

#[cfg(test)]
mod tests;
