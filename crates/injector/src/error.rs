//! Injector errors. No variant carries secret bytes.

use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InjectorError {
    /// The grant JSON is malformed or a required field is missing.
    Grant,
    /// The grant carries no signature. Legacy unsigned grants are refused.
    Unsigned,
    /// The Ed25519 signature or the control-plane key did not verify.
    Signature,
    /// The grant is outside its validity window or claims a long lifetime.
    Expired,
    /// The ids, ciphertext hash, or delivery fields do not match.
    Policy,
    /// The proxy method is not one of the allowed methods.
    Method,
    /// The proxy URL is not a bare `https` URL for the granted host.
    Url,
    /// The request body does not hash to `body_sha256`.
    BodyMismatch,
    /// The secret or the header format would produce an unsafe header.
    HeaderValue,
    /// The ciphertext did not open with the decapsulation key.
    Open,
    /// The upstream request failed.
    Transport,
    /// The upstream response exceeded the size cap.
    ResponseTooLarge,
    /// The upstream response contained the secret.
    Reflected,
    /// A `.env` line could not be parsed.
    Import,
    /// A name cannot be mapped to a secret name, or two names collide.
    Name,
    /// Sealing a value failed.
    Seal,
}

impl fmt::Display for InjectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Grant => "the grant is malformed",
            Self::Unsigned => "the grant is not signed",
            Self::Signature => "the grant signature did not verify",
            Self::Expired => "the grant is expired or not yet valid",
            Self::Policy => "the grant does not match its policy",
            Self::Method => "the grant method is not allowed",
            Self::Url => "the grant url is not allowed",
            Self::BodyMismatch => "the request body does not match the grant",
            Self::HeaderValue => "the header value is not allowed",
            Self::Open => "the ciphertext did not open",
            Self::Transport => "the upstream request failed",
            Self::ResponseTooLarge => "the upstream response is too large",
            Self::Reflected => "the upstream response contained the secret",
            Self::Import => "a .env line could not be parsed",
            Self::Name => "a name cannot be used as a secret name",
            Self::Seal => "sealing failed",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for InjectorError {}
