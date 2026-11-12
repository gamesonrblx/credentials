//! Small JSON, base64, and hash helpers.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::InjectorError;

pub(crate) fn str_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, InjectorError> {
    value
        .get(name)
        .and_then(|v| v.as_str())
        .ok_or(InjectorError::Grant)
}

pub(crate) fn u64_field(value: &Value, name: &str) -> Result<u64, InjectorError> {
    value
        .get(name)
        .and_then(|v| v.as_u64())
        .ok_or(InjectorError::Grant)
}

pub(crate) fn uuid_field(value: &Value, name: &str) -> Result<Uuid, InjectorError> {
    Uuid::parse_str(str_field(value, name)?).map_err(|_| InjectorError::Grant)
}

pub(crate) fn b64_field(value: &Value, name: &str) -> Result<Vec<u8>, InjectorError> {
    b64_decode(str_field(value, name)?)
}

pub(crate) fn b64_decode(text: &str) -> Result<Vec<u8>, InjectorError> {
    STANDARD.decode(text).map_err(|_| InjectorError::Grant)
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn nonce_field(value: &Value, name: &str) -> Result<[u8; 12], InjectorError> {
    b64_field(value, name)?
        .try_into()
        .map_err(|_| InjectorError::Grant)
}

/// Lowercase hex SHA-256.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex(&digest)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// True for 64 lowercase hex characters.
pub(crate) fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build `{"<key>":"<name>","value":"<value>"}` in a buffer that is wiped on drop.
/// The buffer is sized up front so it never reallocates and leaves a copy behind.
pub(crate) fn handoff_json(key: &str, name: &str, value: &str) -> Zeroizing<String> {
    let capacity = 32 + 6 * (key.len() + name.len() + value.len());
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    out.push('{');
    push_json_string(&mut out, key);
    out.push(':');
    push_json_string(&mut out, name);
    out.push_str(",\"value\":");
    push_json_string(&mut out, value);
    out.push('}');
    out
}

fn push_json_string(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32 as usize;
                out.push_str("\\u00");
                out.push(HEX[code >> 4] as char);
                out.push(HEX[code & 0x0f] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_json_escapes_and_parses_back() {
        let text = handoff_json("env_name", "API_KEY", "a\"b\\c\nd\u{1}");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["env_name"], "API_KEY");
        assert_eq!(parsed["value"], "a\"b\\c\nd\u{1}");
    }

    #[test]
    fn sha256_of_empty_body_is_the_known_value() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
