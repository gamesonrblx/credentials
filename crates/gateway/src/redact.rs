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

/// Field formatter for `tracing_subscriber::fmt().fmt_fields(..)`. A field
/// whose name [`redact_field`] matches is written as `[redacted]`.
pub fn redacting_fields(
) -> impl for<'writer> tracing_subscriber::fmt::FormatFields<'writer> + 'static {
    use tracing_subscriber::field::MakeExt;
    tracing_subscriber::fmt::format::debug_fn(write_field).delimited(" ")
}

fn write_field(
    writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
    field: &tracing::field::Field,
    value: &dyn std::fmt::Debug,
) -> std::fmt::Result {
    let name = field.name();
    if name == "message" {
        write!(writer, "{value:?}")
    } else if redact_field(name) {
        write!(writer, "{name}=[redacted]")
    } else {
        write!(writer, "{name}={value:?}")
    }
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
