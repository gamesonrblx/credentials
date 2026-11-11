//! Log field names that must be dropped before anything is written.
//!
//! The gateway does not log request bodies. This list is the backstop for a
//! structured field that slips through.

const REDACTED: &[&str] = &[
    "value",
    "secret",
    "plaintext",
    "password",
    "token",
    "authorization",
    "dpop",
    "dek",
    "kek",
    "wrapped_kek",
    "dek_wrapped",
    "payload_ciphertext",
    "credential",
];

pub fn redact_field(key: &str) -> bool {
    REDACTED.iter().any(|name| key.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_value_is_dropped() {
        let canary = "super-secret-canary";
        let fields = [
            ("value", canary),
            ("secret_name", "prod/openai/api_key"),
            ("authorization", canary),
        ];
        let kept: Vec<_> = fields
            .into_iter()
            .filter(|(key, _)| !redact_field(key))
            .collect();
        assert_eq!(kept, vec![("secret_name", "prod/openai/api_key")]);
        let rendered = format!("{kept:?}");
        assert!(!rendered.contains(canary));
    }
}
