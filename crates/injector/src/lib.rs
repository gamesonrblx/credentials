//! Customer-run injector for end-to-end secrets.
//!
//! The control plane never links this crate. `POST /v1/inject` returns a
//! signed grant for `wrap_mode = e2e`. This crate checks the grant signature
//! and its delivery policy, opens the ciphertext with the workspace
//! decapsulation key, and performs the delivery the grant names. This process
//! does not accept a tenant KEK.

#![forbid(unsafe_code)]

mod deliver;
mod dotenv;
mod error;
mod grant;
mod json;
#[cfg(test)]
mod tests;

pub use deliver::{
    deliver, Delivered, EnvHandoff, HeaderHandoff, Outbound, ProxyResponse, ReqwestTransport,
    Transport, UpstreamResponse, CONNECT_TIMEOUT_SECS, MAX_RESPONSE_BYTES, TOTAL_TIMEOUT_SECS,
};
pub use dotenv::{
    import_dotenv, import_pairs, parse_dotenv, secret_name_for, submission_json, Imported,
    SubmissionPolicy,
};
pub use error::InjectorError;
pub use grant::{
    grant_from_inject_response, verify_grant, GrantDelivery, HttpMethod, ProxyPolicy,
    VerifiedGrant, GRANT_SIGNING_PREFIX, MAX_CLOCK_SKEW_SECS, MAX_GRANT_LIFETIME_SECS,
};
