//! AWS Nitro attestation documents.
//!
//! A document is a COSE_Sign1 payload signed with ES384. The leaf certificate
//! chains to a root the caller pins. CI builds that chain with a test root.
//! Building an EIF needs the Nitro CLI on a Nitro host.

use sha2::{Digest, Sha256};
use x509_cert::der::Decode;

#[derive(Debug)]
pub struct NitroError;

#[derive(Clone, Debug)]
pub struct Attestation {
    pub pcrs: Vec<(u8, [u8; 48])>,
    pub user_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub module_id: String,
}

/// Verify a COSE_Sign1 document against `root_der` and PCR0.
pub fn verify_attestation(
    document: &[u8],
    root_der: &[u8],
    expected_pcr0: &[u8; 48],
) -> Result<Attestation, NitroError> {
    let parsed = parse_sign1(document)?;
    if parsed.pcr0 != *expected_pcr0 {
        return Err(NitroError);
    }
    let leaf_key = public_key(&parsed.certificate)?;
    verify_es384(
        &leaf_key,
        &sig_structure(&parsed.protected, &parsed.payload),
        &parsed.signature,
    )?;
    chain_to_root(&parsed.certificate, &parsed.cabundle, root_der)?;
    Ok(Attestation {
        pcrs: vec![(0, parsed.pcr0)],
        user_data: parsed.user_data,
        nonce: parsed.nonce,
        module_id: parsed.module_id,
    })
}

pub fn release_allowed(attestation: &Attestation, expected_pcr0: &[u8; 48]) -> bool {
    attestation
        .pcrs
        .iter()
        .any(|(index, value)| *index == 0 && value == expected_pcr0)
}

pub fn sha256_der(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

struct Sign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    pcr0: [u8; 48],
    user_data: Vec<u8>,
    nonce: Vec<u8>,
    module_id: String,
}

fn parse_sign1(document: &[u8]) -> Result<Sign1, NitroError> {
    let value: ciborium::Value = ciborium::from_reader(document).map_err(|_| NitroError)?;
    let items = value.as_array().ok_or(NitroError)?;
    if items.len() != 4 {
        return Err(NitroError);
    }
    let protected = bytes_of(&items[0])?;
    let payload = bytes_of(&items[2])?;
    let signature = bytes_of(&items[3])?;
    let header: ciborium::Value =
        ciborium::from_reader(protected.as_slice()).map_err(|_| NitroError)?;
    let alg = map_i64(&header, 1)?;
    if alg != -35 {
        return Err(NitroError);
    }
    let body: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).map_err(|_| NitroError)?;
    let module_id = map_text(&body, "module_id")?;
    let pcrs = map_get(&body, "pcrs")?.ok_or(NitroError)?;
    let pcr0_bytes = map_bytes_at(pcrs, 0)?;
    if pcr0_bytes.len() != 48 {
        return Err(NitroError);
    }
    let mut pcr0 = [0u8; 48];
    pcr0.copy_from_slice(&pcr0_bytes);
    let certificate = map_bytes(&body, "certificate")?;
    let cabundle = map_bytes_list(&body, "cabundle")?;
    let user_data = map_bytes(&body, "user_data").unwrap_or_default();
    let nonce = map_bytes(&body, "nonce").unwrap_or_default();
    Ok(Sign1 {
        protected,
        payload,
        signature,
        certificate,
        cabundle,
        pcr0,
        user_data,
        nonce,
        module_id,
    })
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let value = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_owned()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("cbor");
    out
}

fn verify_es384(point: &[u8], message: &[u8], signature: &[u8]) -> Result<(), NitroError> {
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| NitroError)?;
    let sig = p384::ecdsa::Signature::from_slice(signature).map_err(|_| NitroError)?;
    p384::ecdsa::signature::Verifier::verify(&key, message, &sig).map_err(|_| NitroError)
}

fn chain_to_root(leaf: &[u8], bundle: &[Vec<u8>], root: &[u8]) -> Result<(), NitroError> {
    let mut child = leaf;
    for parent in bundle {
        verify_cert_signed_by(child, parent)?;
        child = parent;
    }
    verify_cert_signed_by(child, root)
}

fn verify_cert_signed_by(child_der: &[u8], parent_der: &[u8]) -> Result<(), NitroError> {
    let (tbs, signature) = split_certificate(child_der)?;
    let parent_key = public_key(parent_der)?;
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&parent_key).map_err(|_| NitroError)?;
    let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| NitroError)?;
    p384::ecdsa::signature::Verifier::verify(&key, tbs, &sig).map_err(|_| NitroError)
}

fn public_key(der: &[u8]) -> Result<Vec<u8>, NitroError> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| NitroError)?;
    let point = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    Ok(point.to_vec())
}

fn split_certificate(der: &[u8]) -> Result<(&[u8], &[u8]), NitroError> {
    let (tag, body, rest) = tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(NitroError);
    }
    let (tbs_tag, _, after_tbs) = tlv(body)?;
    if tbs_tag != 0x30 {
        return Err(NitroError);
    }
    let tbs_len = body.len() - after_tbs.len();
    let tbs = &body[..tbs_len];
    let (_, _, after_alg) = tlv(after_tbs)?;
    let (sig_tag, sig_body, sig_rest) = tlv(after_alg)?;
    if sig_tag != 0x03 || !sig_rest.is_empty() || sig_body.first() != Some(&0) {
        return Err(NitroError);
    }
    Ok((tbs, &sig_body[1..]))
}

fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), NitroError> {
    if input.len() < 2 {
        return Err(NitroError);
    }
    let tag = input[0];
    let (len, header) = der_len(&input[1..])?;
    let rest = &input[1 + header..];
    if rest.len() < len {
        return Err(NitroError);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn der_len(input: &[u8]) -> Result<(usize, usize), NitroError> {
    let first = *input.first().ok_or(NitroError)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let octets = (first & 0x7f) as usize;
    if octets == 0 || octets > 3 || input.len() < 1 + octets {
        return Err(NitroError);
    }
    let mut len = 0usize;
    for byte in &input[1..1 + octets] {
        len = (len << 8) | *byte as usize;
    }
    Ok((len, 1 + octets))
}

fn bytes_of(value: &ciborium::Value) -> Result<Vec<u8>, NitroError> {
    match value {
        ciborium::Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(NitroError),
    }
}

fn map_get<'a>(
    value: &'a ciborium::Value,
    key: &str,
) -> Result<Option<&'a ciborium::Value>, NitroError> {
    let pairs = value.as_map().ok_or(NitroError)?;
    Ok(pairs.iter().find_map(|(name, item)| match name {
        ciborium::Value::Text(text) if text == key => Some(item),
        _ => None,
    }))
}

fn map_text(value: &ciborium::Value, key: &str) -> Result<String, NitroError> {
    match map_get(value, key)?.ok_or(NitroError)? {
        ciborium::Value::Text(text) => Ok(text.clone()),
        _ => Err(NitroError),
    }
}

fn map_bytes(value: &ciborium::Value, key: &str) -> Result<Vec<u8>, NitroError> {
    bytes_of(map_get(value, key)?.ok_or(NitroError)?)
}

fn map_bytes_list(value: &ciborium::Value, key: &str) -> Result<Vec<Vec<u8>>, NitroError> {
    let list = map_get(value, key)?
        .ok_or(NitroError)?
        .as_array()
        .ok_or(NitroError)?;
    list.iter().map(bytes_of).collect()
}

fn map_i64(value: &ciborium::Value, key: i64) -> Result<i64, NitroError> {
    let pairs = value.as_map().ok_or(NitroError)?;
    let found = pairs.iter().find_map(|(name, item)| match name {
        ciborium::Value::Integer(integer) if i64::try_from(*integer).ok() == Some(key) => {
            Some(item)
        }
        _ => None,
    });
    match found.ok_or(NitroError)? {
        ciborium::Value::Integer(integer) => i64::try_from(*integer).map_err(|_| NitroError),
        _ => Err(NitroError),
    }
}

fn map_bytes_at(value: &ciborium::Value, key: i64) -> Result<Vec<u8>, NitroError> {
    let pairs = value.as_map().ok_or(NitroError)?;
    let found = pairs.iter().find_map(|(name, item)| match name {
        ciborium::Value::Integer(integer) if i64::try_from(*integer).ok() == Some(key) => {
            Some(item)
        }
        _ => None,
    });
    bytes_of(found.ok_or(NitroError)?)
}

/// Build a COSE_Sign1 document. Tests use this with a certificate chain they signed.
pub fn seal_document(
    signing: &p384::ecdsa::SigningKey,
    leaf_der: &[u8],
    cabundle: &[Vec<u8>],
    pcr0: &[u8; 48],
    user_data: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let protected_map = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(1.into()),
        ciborium::Value::Integer((-35).into()),
    )]);
    let mut protected = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected).expect("cbor");
    let pcr_pairs = vec![(
        ciborium::Value::Integer(0.into()),
        ciborium::Value::Bytes(pcr0.to_vec()),
    )];
    let payload_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text("test-enclave".into()),
        ),
        (
            ciborium::Value::Text("pcrs".into()),
            ciborium::Value::Map(pcr_pairs),
        ),
        (
            ciborium::Value::Text("certificate".into()),
            ciborium::Value::Bytes(leaf_der.to_vec()),
        ),
        (
            ciborium::Value::Text("cabundle".into()),
            ciborium::Value::Array(
                cabundle
                    .iter()
                    .cloned()
                    .map(ciborium::Value::Bytes)
                    .collect(),
            ),
        ),
        (
            ciborium::Value::Text("user_data".into()),
            ciborium::Value::Bytes(user_data.to_vec()),
        ),
        (
            ciborium::Value::Text("nonce".into()),
            ciborium::Value::Bytes(nonce.to_vec()),
        ),
    ]);
    let mut payload = Vec::new();
    ciborium::into_writer(&payload_map, &mut payload).expect("cbor");
    let signature: p384::ecdsa::Signature =
        p384::ecdsa::signature::Signer::sign(signing, &sig_structure(&protected, &payload));
    let document = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        ciborium::Value::Map(Vec::new()),
        ciborium::Value::Bytes(payload),
        ciborium::Value::Bytes(signature.to_bytes().to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&document, &mut out).expect("cbor");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> (Vec<u8>, Vec<u8>, p384::ecdsa::SigningKey) {
        let root_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut root_params = rcgen::CertificateParams::new(vec!["nitro-root".into()]).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = rcgen::CertifiedIssuer::self_signed(root_params, root_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["enclave".into()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &root).unwrap();
        let signing =
            p384::pkcs8::DecodePrivateKey::from_pkcs8_der(leaf_key.serialized_der()).unwrap();
        (root.der().to_vec(), leaf.der().to_vec(), signing)
    }

    #[test]
    fn a_wrong_pcr_or_root_is_rejected() {
        let (root, leaf, signing) = chain();
        let pcr = [7u8; 48];
        let doc = seal_document(&signing, &leaf, &[], &pcr, b"nonce", b"user");
        let ok = verify_attestation(&doc, &root, &pcr).unwrap();
        assert!(release_allowed(&ok, &pcr));
        assert_eq!(ok.module_id, "test-enclave");
        assert!(verify_attestation(&doc, &root, &[8u8; 48]).is_err());
        let (other_root, _, _) = chain();
        assert!(verify_attestation(&doc, &other_root, &pcr).is_err());
        let mut broken = doc.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0xff;
        assert!(verify_attestation(&broken, &root, &pcr).is_err());
    }
}
