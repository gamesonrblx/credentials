//! Adapters that sit beside the control plane.
//!
//! The hosted control plane still uses `RejectingRootKeys`. These types
//! run in the customer injector, a dev process, or an attested enclave.
//! None of them adds an operator recovery recipient.

pub mod aws_kms;
pub mod importers;
pub mod nitro;
pub mod oidc;
pub mod s3lock;
pub mod vault;
pub mod webauthn;

pub use aws_kms::{amz_now, authorization, kms_key_policy, AwsKms, KmsError};
pub use importers::{read_doppler, read_infisical, read_onepassword, read_vault_kv, SourceSecret};
pub use nitro::{verify_attestation, Attestation, NitroError};
pub use oidc::{authorize_url, exchange_code, CodeChallenge, OidcClient, OidcError};
pub use s3lock::{put_locked, LockError, LockedObject};
pub use vault::VaultTransit;
pub use webauthn::{authenticate, register, Authenticator, RelyingParty, WebauthnError};

#[cfg(test)]
mod tests;
