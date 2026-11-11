use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::ApiError;

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(text: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| ApiError::BadRequest)
}

pub fn b64std_decode(text: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD
        .decode(text.trim())
        .map_err(|_| ApiError::BadRequest)
}

pub fn b64std_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
