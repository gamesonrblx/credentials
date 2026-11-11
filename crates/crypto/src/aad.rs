//! Associated data for payload encryption and DEK wrapping.
//!
//! Layouts are normative in `docs/ENCRYPTION.md` section 5. A future encoding
//! uses a new magic. Writers here emit `CRD1` only.

use uuid::Uuid;

pub const MAGIC: &[u8; 4] = b"CRD1";
pub const PURPOSE_PAYLOAD: u8 = 0x01;
pub const PURPOSE_DEK: u8 = 0x02;
pub const ALG_AES_256_GCM_V1: u8 = 0x01;

pub const PAYLOAD_AAD_LEN: usize = 54;
pub const DEK_AAD_LEN: usize = 74;

/// 54-byte payload associated data.
pub fn payload_aad(workspace_id: Uuid, secret_id: Uuid, version_id: Uuid) -> [u8; PAYLOAD_AAD_LEN] {
    let mut out = [0u8; PAYLOAD_AAD_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4] = PURPOSE_PAYLOAD;
    out[5..21].copy_from_slice(workspace_id.as_bytes());
    out[21..37].copy_from_slice(secret_id.as_bytes());
    out[37..53].copy_from_slice(version_id.as_bytes());
    out[53] = ALG_AES_256_GCM_V1;
    out
}

/// 74-byte DEK-wrap associated data.
pub fn dek_aad(
    workspace_id: Uuid,
    secret_id: Uuid,
    version_id: Uuid,
    kek_id: Uuid,
    kek_version: u32,
) -> [u8; DEK_AAD_LEN] {
    let mut out = [0u8; DEK_AAD_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4] = PURPOSE_DEK;
    out[5..21].copy_from_slice(workspace_id.as_bytes());
    out[21..37].copy_from_slice(secret_id.as_bytes());
    out[37..53].copy_from_slice(version_id.as_bytes());
    out[53..69].copy_from_slice(kek_id.as_bytes());
    out[69..73].copy_from_slice(&kek_version.to_be_bytes());
    out[73] = ALG_AES_256_GCM_V1;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).unwrap()
    }

    #[test]
    fn payload_known_answer() {
        let aad = payload_aad(
            uuid("00000000-0000-7000-8000-000000000001"),
            uuid("00000000-0000-7000-8000-000000000002"),
            uuid("00000000-0000-7000-8000-000000000003"),
        );
        let expected = hex(
            "435244310100000000000070008000000000000001000000000000700080000000000000020000000000007000800000000000000301",
        );
        assert_eq!(aad.as_slice(), expected.as_slice());
    }

    #[test]
    fn dek_known_answer() {
        let aad = dek_aad(
            uuid("00000000-0000-7000-8000-000000000001"),
            uuid("00000000-0000-7000-8000-000000000002"),
            uuid("00000000-0000-7000-8000-000000000003"),
            uuid("00000000-0000-7000-8000-000000000004"),
            1,
        );
        let expected = hex(
            "4352443102000000000000700080000000000000010000000000007000800000000000000200000000000070008000000000000003000000000000700080000000000000040000000101",
        );
        assert_eq!(aad.as_slice(), expected.as_slice());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
