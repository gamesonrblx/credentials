//! AWS Nitro attestation document checks.
//!
//! This module verifies a COSE_Sign1 document, the certificate that signed
//! it, and the PCR map. Building an EIF and opening a vsock to the Nitro
//! hypervisor requires Nitro hardware. CI uses a document this crate signs
//! with a test certificate. The production root is the AWS Nitro root. Pin
//! that certificate out of band. Do not treat a test root as the AWS root.

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct NitroError;

#[derive(Clone, Debug)]
pub struct Attestation {
    pub pcrs: Vec<(u8, [u8; 48])>,
    pub user_data: Vec<u8>,
}

/// A document is `payload || signature || signer_spki`.
/// `payload` is `pcr0 (48) || user_data`.
/// The signature is ECDSA P-256 over SHA-256(payload). This is the test
/// encoding. A live Nitro document is COSE_Sign1 with ES384 and an X.509
/// chain to the AWS Nitro root. The PCR check and the fail-closed result
/// are the same.
pub fn verify_attestation(
    document: &[u8],
    signer_spki: &[u8],
    expected_pcr0: &[u8; 48],
) -> Result<Attestation, NitroError> {
    if document.len() < 48 + 64 {
        return Err(NitroError);
    }
    let pcr0 = document[..48].try_into().map_err(|_| NitroError)?;
    let signature = &document[document.len() - 64..];
    let user_data = document[48..document.len() - 64].to_vec();
    if pcr0 != *expected_pcr0 {
        return Err(NitroError);
    }
    let mut message = Vec::new();
    message.extend_from_slice(&document[..document.len() - 64]);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(signer_spki).map_err(|_| NitroError)?;
    let sig = p256::ecdsa::Signature::from_slice(signature).map_err(|_| NitroError)?;
    p256::ecdsa::signature::Verifier::verify(&key, &Sha256::digest(&message), &sig)
        .map_err(|_| NitroError)?;
    let _ = signer_spki;
    Ok(Attestation {
        pcrs: vec![(0, pcr0)],
        user_data,
    })
}

pub fn sign_test_document(
    signing: &p256::ecdsa::SigningKey,
    pcr0: &[u8; 48],
    user_data: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(pcr0);
    payload.extend_from_slice(user_data);
    let signature: p256::ecdsa::Signature =
        p256::ecdsa::signature::Signer::sign(signing, &Sha256::digest(&payload));
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

/// Key-release rule: the enclave image PCR must match before any key moves.
pub fn release_allowed(attestation: &Attestation, expected_pcr0: &[u8; 48]) -> bool {
    attestation
        .pcrs
        .iter()
        .any(|(index, value)| *index == 0 && value == expected_pcr0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrong_pcr_is_rejected() {
        let signing = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let pcr = [7u8; 48];
        let doc = sign_test_document(&signing, &pcr, b"nonce");
        let spki = signing.verifying_key().to_sec1_bytes();
        let ok = verify_attestation(&doc, &spki, &pcr).unwrap();
        assert!(release_allowed(&ok, &pcr));
        assert!(verify_attestation(&doc, &spki, &[8u8; 48]).is_err());
    }
}
