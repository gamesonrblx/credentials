//! AWS Nitro attestation documents.
//!
//! A document is a COSE_Sign1 payload signed with ES384. The leaf certificate
//! chains through `cabundle` to a root the caller pins. AWS orders `cabundle`
//! root first, so the path runs from the leaf to the last bundle entry and
//! then back to `cabundle[0]`, which must be the pinned root.
//!
//! CI builds that chain with a test root. Building an EIF needs the Nitro CLI
//! on a Nitro host. The gateway does not call this module yet.
//!
//! Not checked: revocation, key usage, and unknown critical extensions.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use x509_cert::der::Decode;

/// Why a document was rejected. No variant carries document bytes.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NitroError {
    #[error("attestation document is malformed")]
    Malformed,
    #[error("attestation document uses an unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("attestation signature does not verify")]
    BadSignature,
    #[error("certificate bundle does not start with the pinned root")]
    UntrustedRoot,
    #[error("certificate chain does not verify")]
    BrokenChain,
    #[error("a certificate is outside its validity period")]
    CertificateNotValidNow,
    #[error("an issuing certificate is not a CA")]
    NotCa,
    #[error("the chain exceeds a path length constraint")]
    PathLength,
    #[error("the policy lists no expected PCRs")]
    NoExpectedPcrs,
    #[error("a PCR does not match the policy")]
    PcrMismatch,
    #[error("attestation timestamp is outside the accepted window")]
    Stale,
    #[error("attestation nonce does not match")]
    NonceMismatch,
}

/// What the caller trusts when it verifies a document.
#[derive(Clone, Debug)]
pub struct AttestationPolicy {
    /// DER of the pinned root. It must equal `cabundle[0]` byte for byte.
    pub root_der: Vec<u8>,
    /// PCR index to the SHA-384 value it must hold. It must not be empty.
    pub expected_pcrs: BTreeMap<u8, [u8; 48]>,
    /// Oldest accepted document, in seconds before the verification time.
    pub max_age_secs: u64,
    /// The nonce the caller asked the enclave to embed, if any.
    pub expected_nonce: Option<Vec<u8>>,
}

impl AttestationPolicy {
    /// A policy that pins PCR0 only and expects no nonce.
    pub fn pcr0(root_der: Vec<u8>, pcr0: [u8; 48], max_age_secs: u64) -> Self {
        let mut expected_pcrs = BTreeMap::new();
        expected_pcrs.insert(0, pcr0);
        Self {
            root_der,
            expected_pcrs,
            max_age_secs,
            expected_nonce: None,
        }
    }
}

/// A verified document. The optional fields are what the enclave bound into it.
#[derive(Clone, Debug)]
pub struct Attestation {
    /// Every PCR in the document, sorted by index.
    pub pcrs: Vec<(u8, [u8; 48])>,
    pub module_id: String,
    /// Milliseconds since the Unix epoch, as stamped by the Nitro hypervisor.
    pub timestamp_ms: u64,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

/// A document may be stamped at most this far ahead of the verifier's clock.
const MAX_FUTURE_SKEW_MS: u64 = 60_000;
/// Longest `cabundle` accepted. AWS sends four today.
const MAX_BUNDLE: usize = 8;
/// DER of the AlgorithmIdentifier body for ecdsa-with-SHA384.
const ECDSA_SHA384_ALG: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// DER body of the basicConstraints OID, 2.5.29.19.
const BASIC_CONSTRAINTS_OID: [u8; 3] = [0x55, 0x1d, 0x13];

/// Verify a COSE_Sign1 document against `policy` at `now_unix` seconds.
///
/// `cabundle[0]` must be the pinned root. An empty bundle is rejected, even
/// when the leaf is signed by the root directly, because AWS always sends the
/// root in the bundle. Every certificate must be valid at `now_unix`, every
/// issuer must be a CA, every PCR in the policy must match, and the document
/// must be no older than `policy.max_age_secs`.
pub fn verify_attestation(
    document: &[u8],
    policy: &AttestationPolicy,
    now_unix: u64,
) -> Result<Attestation, NitroError> {
    if policy.expected_pcrs.is_empty() {
        return Err(NitroError::NoExpectedPcrs);
    }
    let parsed = parse_sign1(document)?;
    let leaf_key = public_key(&parsed.certificate)?;
    verify_es384(
        &leaf_key,
        &sig_structure(&parsed.protected, &parsed.payload)?,
        &parsed.signature,
    )?;
    chain_to_root(
        &parsed.certificate,
        &parsed.cabundle,
        &policy.root_der,
        now_unix,
    )?;
    check_freshness(parsed.timestamp_ms, now_unix, policy.max_age_secs)?;
    for (index, expected) in &policy.expected_pcrs {
        match parsed.pcrs.get(index) {
            Some(value) if value == expected => {}
            _ => return Err(NitroError::PcrMismatch),
        }
    }
    if let Some(expected) = &policy.expected_nonce {
        if parsed.nonce.as_deref() != Some(expected.as_slice()) {
            return Err(NitroError::NonceMismatch);
        }
    }
    Ok(Attestation {
        pcrs: parsed.pcrs.into_iter().collect(),
        module_id: parsed.module_id,
        timestamp_ms: parsed.timestamp_ms,
        public_key: parsed.public_key,
        user_data: parsed.user_data,
        nonce: parsed.nonce,
    })
}

fn check_freshness(timestamp_ms: u64, now_unix: u64, max_age_secs: u64) -> Result<(), NitroError> {
    let now_ms = now_unix.saturating_mul(1000);
    if timestamp_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
        return Err(NitroError::Stale);
    }
    if now_ms.saturating_sub(timestamp_ms) > max_age_secs.saturating_mul(1000) {
        return Err(NitroError::Stale);
    }
    Ok(())
}

/// True when the verified document carries `expected_pcr0` as PCR0.
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
    pcrs: BTreeMap<u8, [u8; 48]>,
    timestamp_ms: u64,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    module_id: String,
}

fn parse_sign1(document: &[u8]) -> Result<Sign1, NitroError> {
    let value: ciborium::Value =
        ciborium::from_reader(document).map_err(|_| NitroError::Malformed)?;
    // COSE allows the Sign1 array with or without CBOR tag 18.
    let value = match value {
        ciborium::Value::Tag(18, inner) => *inner,
        other => other,
    };
    let items = value.as_array().ok_or(NitroError::Malformed)?;
    if items.len() != 4 {
        return Err(NitroError::Malformed);
    }
    let protected = bytes_of(&items[0])?;
    let payload = bytes_of(&items[2])?;
    let signature = bytes_of(&items[3])?;
    let header: ciborium::Value =
        ciborium::from_reader(protected.as_slice()).map_err(|_| NitroError::Malformed)?;
    let alg = map_i64(&header, 1)?;
    if alg != -35 {
        return Err(NitroError::UnsupportedAlgorithm);
    }
    let body: ciborium::Value =
        ciborium::from_reader(payload.as_slice()).map_err(|_| NitroError::Malformed)?;
    let module_id = map_text(&body, "module_id")?;
    if map_text(&body, "digest")? != "SHA384" {
        return Err(NitroError::UnsupportedAlgorithm);
    }
    let timestamp_ms = map_u64(&body, "timestamp")?;
    let pcrs = parse_pcrs(map_get(&body, "pcrs")?.ok_or(NitroError::Malformed)?)?;
    let certificate = map_bytes(&body, "certificate")?;
    let cabundle = map_bytes_list(&body, "cabundle")?;
    let public_key = map_optional_bytes(&body, "public_key")?;
    let user_data = map_optional_bytes(&body, "user_data")?;
    let nonce = map_optional_bytes(&body, "nonce")?;
    Ok(Sign1 {
        protected,
        payload,
        signature,
        certificate,
        cabundle,
        pcrs,
        timestamp_ms,
        public_key,
        user_data,
        nonce,
        module_id,
    })
}

fn parse_pcrs(value: &ciborium::Value) -> Result<BTreeMap<u8, [u8; 48]>, NitroError> {
    let pairs = value.as_map().ok_or(NitroError::Malformed)?;
    let mut out = BTreeMap::new();
    for (key, item) in pairs {
        let index = match key {
            ciborium::Value::Integer(integer) => {
                u8::try_from(*integer).map_err(|_| NitroError::Malformed)?
            }
            _ => return Err(NitroError::Malformed),
        };
        let bytes = match item {
            ciborium::Value::Bytes(bytes) => bytes,
            _ => return Err(NitroError::Malformed),
        };
        let pcr: [u8; 48] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| NitroError::Malformed)?;
        if out.insert(index, pcr).is_some() {
            return Err(NitroError::Malformed);
        }
    }
    Ok(out)
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, NitroError> {
    let value = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_owned()),
        ciborium::Value::Bytes(protected.to_vec()),
        ciborium::Value::Bytes(Vec::new()),
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).map_err(|_| NitroError::Malformed)?;
    Ok(out)
}

fn verify_es384(point: &[u8], message: &[u8], signature: &[u8]) -> Result<(), NitroError> {
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|_| NitroError::UnsupportedAlgorithm)?;
    let sig =
        p384::ecdsa::Signature::from_slice(signature).map_err(|_| NitroError::BadSignature)?;
    p384::ecdsa::signature::Verifier::verify(&key, message, &sig)
        .map_err(|_| NitroError::BadSignature)
}

/// Walk leaf <- cabundle[last] <- ... <- cabundle[0] and require
/// `cabundle[0]` to be the pinned root.
fn chain_to_root(
    leaf: &[u8],
    bundle: &[Vec<u8>],
    root: &[u8],
    now_unix: u64,
) -> Result<(), NitroError> {
    let first = bundle.first().ok_or(NitroError::UntrustedRoot)?;
    if bundle.len() > MAX_BUNDLE {
        return Err(NitroError::BrokenChain);
    }
    // The pin is the exact DER, not "some self-signed certificate".
    if first.as_slice() != root {
        return Err(NitroError::UntrustedRoot);
    }
    let now = i64::try_from(now_unix).map_err(|_| NitroError::CertificateNotValidNow)?;
    let mut path: Vec<&[u8]> = Vec::with_capacity(bundle.len() + 1);
    path.push(leaf);
    path.extend(bundle.iter().rev().map(Vec::as_slice));
    let parsed = path
        .iter()
        .copied()
        .map(parse_certificate)
        .collect::<Result<Vec<_>, _>>()?;
    for cert in &parsed {
        if now < cert.not_before || now > cert.not_after {
            return Err(NitroError::CertificateNotValidNow);
        }
    }
    for (position, pair) in parsed.windows(2).enumerate() {
        let (child, parent) = (&pair[0], &pair[1]);
        let constraints = parent.basic_constraints.ok_or(NitroError::NotCa)?;
        if !constraints.ca {
            return Err(NitroError::NotCa);
        }
        // `position` is the number of CA certificates between this issuer and the leaf.
        if let Some(limit) = constraints.path_len {
            if (position as u64) > limit {
                return Err(NitroError::PathLength);
            }
        }
        if child.issuer != parent.subject {
            return Err(NitroError::BrokenChain);
        }
        verify_cert_signed_by(child, path[position + 1])?;
    }
    Ok(())
}

fn verify_cert_signed_by(child: &CertInfo<'_>, parent_der: &[u8]) -> Result<(), NitroError> {
    let parent_key = public_key(parent_der)?;
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&parent_key)
        .map_err(|_| NitroError::BrokenChain)?;
    let sig =
        p384::ecdsa::Signature::from_der(child.signature).map_err(|_| NitroError::BrokenChain)?;
    p384::ecdsa::signature::Verifier::verify(&key, child.tbs, &sig)
        .map_err(|_| NitroError::BrokenChain)
}

fn public_key(der: &[u8]) -> Result<Vec<u8>, NitroError> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| NitroError::Malformed)?;
    let point = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    Ok(point.to_vec())
}

#[derive(Clone, Copy)]
struct BasicConstraints {
    ca: bool,
    path_len: Option<u64>,
}

/// The parts of a certificate the chain walk needs, read from its DER.
struct CertInfo<'a> {
    tbs: &'a [u8],
    signature: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: i64,
    not_after: i64,
    basic_constraints: Option<BasicConstraints>,
}

fn parse_certificate(der: &[u8]) -> Result<CertInfo<'_>, NitroError> {
    let (tag, body, rest) = tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(NitroError::Malformed);
    }
    let (tbs_tag, tbs_body, after_tbs) = tlv(body)?;
    if tbs_tag != 0x30 {
        return Err(NitroError::Malformed);
    }
    let tbs = &body[..body.len() - after_tbs.len()];
    let (alg_tag, alg_body, after_alg) = tlv(after_tbs)?;
    if alg_tag != 0x30 || alg_body != ECDSA_SHA384_ALG {
        return Err(NitroError::UnsupportedAlgorithm);
    }
    let (sig_tag, sig_body, sig_rest) = tlv(after_alg)?;
    if sig_tag != 0x03 || !sig_rest.is_empty() || sig_body.first() != Some(&0) {
        return Err(NitroError::Malformed);
    }
    let signature = &sig_body[1..];

    let mut cursor = tbs_body;
    let (first_tag, _, after_version) = tlv(cursor)?;
    if first_tag == 0xa0 {
        cursor = after_version;
    }
    let (serial_tag, _, after_serial) = tlv(cursor)?;
    if serial_tag != 0x02 {
        return Err(NitroError::Malformed);
    }
    let (inner_alg_tag, _, after_inner_alg) = tlv(after_serial)?;
    if inner_alg_tag != 0x30 {
        return Err(NitroError::Malformed);
    }
    let (issuer, after_issuer) = element(after_inner_alg, 0x30)?;
    let (validity_tag, validity, after_validity) = tlv(after_issuer)?;
    if validity_tag != 0x30 {
        return Err(NitroError::Malformed);
    }
    let (before_tag, before_body, after_before) = tlv(validity)?;
    let (after_tag, after_body, validity_rest) = tlv(after_before)?;
    if !validity_rest.is_empty() {
        return Err(NitroError::Malformed);
    }
    let not_before = parse_time(before_tag, before_body)?;
    let not_after = parse_time(after_tag, after_body)?;
    let (subject, after_subject) = element(after_validity, 0x30)?;
    let (spki_tag, _, mut cursor) = tlv(after_subject)?;
    if spki_tag != 0x30 {
        return Err(NitroError::Malformed);
    }
    let mut basic_constraints = None;
    while !cursor.is_empty() {
        let (tag, value, next) = tlv(cursor)?;
        cursor = next;
        if tag == 0xa3 {
            basic_constraints = find_basic_constraints(value)?;
        }
    }
    Ok(CertInfo {
        tbs,
        signature,
        issuer,
        subject,
        not_before,
        not_after,
        basic_constraints,
    })
}

/// Return a whole TLV element (header included) with the expected tag.
fn element(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), NitroError> {
    let (tag, _, rest) = tlv(input)?;
    if tag != expected_tag {
        return Err(NitroError::Malformed);
    }
    Ok((&input[..input.len() - rest.len()], rest))
}

fn find_basic_constraints(explicit: &[u8]) -> Result<Option<BasicConstraints>, NitroError> {
    let (seq_tag, mut extensions, rest) = tlv(explicit)?;
    if seq_tag != 0x30 || !rest.is_empty() {
        return Err(NitroError::Malformed);
    }
    let mut found = None;
    while !extensions.is_empty() {
        let (ext_tag, ext, next) = tlv(extensions)?;
        extensions = next;
        if ext_tag != 0x30 {
            return Err(NitroError::Malformed);
        }
        let (oid_tag, oid, mut fields) = tlv(ext)?;
        if oid_tag != 0x06 {
            return Err(NitroError::Malformed);
        }
        if oid != BASIC_CONSTRAINTS_OID {
            continue;
        }
        if found.is_some() {
            return Err(NitroError::Malformed);
        }
        let (mut tag, mut value, mut after) = tlv(fields)?;
        if tag == 0x01 {
            fields = after;
            (tag, value, after) = tlv(fields)?;
        }
        if tag != 0x04 || !after.is_empty() {
            return Err(NitroError::Malformed);
        }
        let (bc_tag, mut bc, bc_rest) = tlv(value)?;
        if bc_tag != 0x30 || !bc_rest.is_empty() {
            return Err(NitroError::Malformed);
        }
        let mut constraints = BasicConstraints {
            ca: false,
            path_len: None,
        };
        if !bc.is_empty() {
            let (tag, value, next) = tlv(bc)?;
            if tag == 0x01 {
                constraints.ca = value == [0xff];
                bc = next;
            }
        }
        if !bc.is_empty() {
            let (tag, value, next) = tlv(bc)?;
            if tag != 0x02 || !next.is_empty() || value.is_empty() || value.len() > 8 {
                return Err(NitroError::Malformed);
            }
            if value[0] & 0x80 != 0 {
                return Err(NitroError::Malformed);
            }
            let limit = value
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            constraints.path_len = Some(limit);
        }
        found = Some(constraints);
    }
    Ok(found)
}

/// Parse an RFC 5280 UTCTime or GeneralizedTime into Unix seconds.
fn parse_time(tag: u8, body: &[u8]) -> Result<i64, NitroError> {
    let digits = match (tag, body.len()) {
        (0x17, 13) | (0x18, 15) => &body[..body.len() - 1],
        _ => return Err(NitroError::Malformed),
    };
    if body.last() != Some(&b'Z') || !digits.iter().all(u8::is_ascii_digit) {
        return Err(NitroError::Malformed);
    }
    let number = |range: std::ops::Range<usize>| -> i64 {
        digits[range]
            .iter()
            .fold(0i64, |acc, digit| acc * 10 + i64::from(digit - b'0'))
    };
    let (year, rest) = if tag == 0x17 {
        let short = number(0..2);
        (
            if short >= 50 {
                1900 + short
            } else {
                2000 + short
            },
            2,
        )
    } else {
        (number(0..4), 4)
    };
    let month = number(rest..rest + 2);
    let day = number(rest + 2..rest + 4);
    let hour = number(rest + 4..rest + 6);
    let minute = number(rest + 6..rest + 8);
    let second = number(rest + 8..rest + 10);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(NitroError::Malformed);
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), NitroError> {
    if input.len() < 2 {
        return Err(NitroError::Malformed);
    }
    let tag = input[0];
    let (len, header) = der_len(&input[1..])?;
    let rest = &input[1 + header..];
    if rest.len() < len {
        return Err(NitroError::Malformed);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn der_len(input: &[u8]) -> Result<(usize, usize), NitroError> {
    let first = *input.first().ok_or(NitroError::Malformed)?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let octets = (first & 0x7f) as usize;
    if octets == 0 || octets > 3 || input.len() < 1 + octets {
        return Err(NitroError::Malformed);
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
        _ => Err(NitroError::Malformed),
    }
}

fn map_get<'a>(
    value: &'a ciborium::Value,
    key: &str,
) -> Result<Option<&'a ciborium::Value>, NitroError> {
    let pairs = value.as_map().ok_or(NitroError::Malformed)?;
    Ok(pairs.iter().find_map(|(name, item)| match name {
        ciborium::Value::Text(text) if text == key => Some(item),
        _ => None,
    }))
}

fn map_text(value: &ciborium::Value, key: &str) -> Result<String, NitroError> {
    match map_get(value, key)?.ok_or(NitroError::Malformed)? {
        ciborium::Value::Text(text) => Ok(text.clone()),
        _ => Err(NitroError::Malformed),
    }
}

fn map_u64(value: &ciborium::Value, key: &str) -> Result<u64, NitroError> {
    match map_get(value, key)?.ok_or(NitroError::Malformed)? {
        ciborium::Value::Integer(integer) => {
            u64::try_from(*integer).map_err(|_| NitroError::Malformed)
        }
        _ => Err(NitroError::Malformed),
    }
}

fn map_bytes(value: &ciborium::Value, key: &str) -> Result<Vec<u8>, NitroError> {
    bytes_of(map_get(value, key)?.ok_or(NitroError::Malformed)?)
}

/// An optional field is absent, CBOR null, or a byte string.
fn map_optional_bytes(value: &ciborium::Value, key: &str) -> Result<Option<Vec<u8>>, NitroError> {
    match map_get(value, key)? {
        None | Some(ciborium::Value::Null) => Ok(None),
        Some(item) => bytes_of(item).map(Some),
    }
}

fn map_bytes_list(value: &ciborium::Value, key: &str) -> Result<Vec<Vec<u8>>, NitroError> {
    let list = map_get(value, key)?
        .ok_or(NitroError::Malformed)?
        .as_array()
        .ok_or(NitroError::Malformed)?;
    list.iter().map(bytes_of).collect()
}

fn map_i64(value: &ciborium::Value, key: i64) -> Result<i64, NitroError> {
    let pairs = value.as_map().ok_or(NitroError::Malformed)?;
    let found = pairs.iter().find_map(|(name, item)| match name {
        ciborium::Value::Integer(integer) if i64::try_from(*integer).ok() == Some(key) => {
            Some(item)
        }
        _ => None,
    });
    match found.ok_or(NitroError::Malformed)? {
        ciborium::Value::Integer(integer) => {
            i64::try_from(*integer).map_err(|_| NitroError::Malformed)
        }
        _ => Err(NitroError::Malformed),
    }
}

/// Fields a test puts in a document built with [`seal_document`].
#[cfg(any(test, feature = "test-util"))]
pub struct SealFields<'a> {
    pub pcrs: &'a [(u8, [u8; 48])],
    pub timestamp_ms: u64,
    pub public_key: Option<&'a [u8]>,
    pub user_data: Option<&'a [u8]>,
    pub nonce: Option<&'a [u8]>,
}

/// Build a COSE_Sign1 document. Tests use this with a certificate chain they signed.
#[cfg(any(test, feature = "test-util"))]
pub fn seal_document(
    signing: &p384::ecdsa::SigningKey,
    leaf_der: &[u8],
    cabundle: &[Vec<u8>],
    fields: &SealFields<'_>,
) -> Result<Vec<u8>, NitroError> {
    let protected_map = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(1.into()),
        ciborium::Value::Integer((-35).into()),
    )]);
    let mut protected = Vec::new();
    ciborium::into_writer(&protected_map, &mut protected).map_err(|_| NitroError::Malformed)?;
    let pcr_pairs: Vec<(ciborium::Value, ciborium::Value)> = fields
        .pcrs
        .iter()
        .map(|(index, value)| {
            (
                ciborium::Value::Integer((*index).into()),
                ciborium::Value::Bytes(value.to_vec()),
            )
        })
        .collect();
    let optional = |value: Option<&[u8]>| match value {
        Some(bytes) => ciborium::Value::Bytes(bytes.to_vec()),
        None => ciborium::Value::Null,
    };
    let payload_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("module_id".into()),
            ciborium::Value::Text("test-enclave".into()),
        ),
        (
            ciborium::Value::Text("digest".into()),
            ciborium::Value::Text("SHA384".into()),
        ),
        (
            ciborium::Value::Text("timestamp".into()),
            ciborium::Value::Integer(fields.timestamp_ms.into()),
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
            ciborium::Value::Text("public_key".into()),
            optional(fields.public_key),
        ),
        (
            ciborium::Value::Text("user_data".into()),
            optional(fields.user_data),
        ),
        (
            ciborium::Value::Text("nonce".into()),
            optional(fields.nonce),
        ),
    ]);
    let mut payload = Vec::new();
    ciborium::into_writer(&payload_map, &mut payload).map_err(|_| NitroError::Malformed)?;
    let signature: p384::ecdsa::Signature =
        p384::ecdsa::signature::Signer::sign(signing, &sig_structure(&protected, &payload)?);
    let document = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        ciborium::Value::Map(Vec::new()),
        ciborium::Value::Bytes(payload),
        ciborium::Value::Bytes(signature.to_bytes().to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&document, &mut out).map_err(|_| NitroError::Malformed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints as Bc, IsCa};

    const MAX_AGE: u64 = 300;

    fn now() -> u64 {
        (days_from_civil(2026, 6, 1) * 86_400) as u64
    }

    struct Chain {
        root: Vec<u8>,
        intermediate: Vec<u8>,
        leaf: Vec<u8>,
        signing: p384::ecdsa::SigningKey,
    }

    fn params(name: &str, is_ca: IsCa, years: (i32, i32)) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = is_ca;
        params.not_before = rcgen::date_time_ymd(years.0, 1, 1);
        params.not_after = rcgen::date_time_ymd(years.1, 1, 1);
        params
    }

    fn key() -> rcgen::KeyPair {
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap()
    }

    /// Root -> intermediate -> leaf, all P-384 with ECDSA-SHA384.
    fn chain_with(root_ca: IsCa, intermediate_ca: IsCa, leaf_years: (i32, i32)) -> Chain {
        let root =
            rcgen::CertifiedIssuer::self_signed(params("nitro-root", root_ca, (2020, 2060)), key())
                .unwrap();
        let intermediate = rcgen::CertifiedIssuer::signed_by(
            params("nitro-intermediate", intermediate_ca, (2020, 2060)),
            key(),
            &root,
        )
        .unwrap();
        let leaf_key = key();
        let leaf = params("enclave", IsCa::NoCa, leaf_years)
            .signed_by(&leaf_key, &intermediate)
            .unwrap();
        let signing: p384::ecdsa::SigningKey =
            p384::pkcs8::DecodePrivateKey::from_pkcs8_der(leaf_key.serialized_der()).unwrap();
        Chain {
            root: root.der().to_vec(),
            intermediate: intermediate.der().to_vec(),
            leaf: leaf.der().to_vec(),
            signing,
        }
    }

    fn good_chain() -> Chain {
        chain_with(
            IsCa::Ca(Bc::Unconstrained),
            IsCa::Ca(Bc::Unconstrained),
            (2026, 2027),
        )
    }

    const PCRS: [(u8, [u8; 48]); 3] = [(0, [7u8; 48]), (1, [1u8; 48]), (2, [2u8; 48])];

    fn fields(timestamp_ms: u64) -> SealFields<'static> {
        SealFields {
            pcrs: &PCRS,
            timestamp_ms,
            public_key: Some(b"enclave-public-key"),
            user_data: Some(b"user"),
            nonce: Some(b"nonce-1"),
        }
    }

    /// A document in AWS order: cabundle = [root, intermediate].
    fn aws_document(chain: &Chain) -> Vec<u8> {
        seal(chain, &[chain.root.clone(), chain.intermediate.clone()])
    }

    fn seal(chain: &Chain, bundle: &[Vec<u8>]) -> Vec<u8> {
        seal_document(
            &chain.signing,
            &chain.leaf,
            bundle,
            &fields(now() * 1000 - 1000),
        )
        .unwrap()
    }

    fn policy(chain: &Chain) -> AttestationPolicy {
        let mut expected_pcrs = BTreeMap::new();
        expected_pcrs.insert(0, [7u8; 48]);
        expected_pcrs.insert(2, [2u8; 48]);
        AttestationPolicy {
            root_der: chain.root.clone(),
            expected_pcrs,
            max_age_secs: MAX_AGE,
            expected_nonce: Some(b"nonce-1".to_vec()),
        }
    }

    #[test]
    fn an_aws_ordered_chain_verifies_and_returns_the_bound_fields() {
        let chain = good_chain();
        let doc = aws_document(&chain);
        let ok = verify_attestation(&doc, &policy(&chain), now()).unwrap();
        assert!(release_allowed(&ok, &[7u8; 48]));
        assert_eq!(ok.module_id, "test-enclave");
        assert_eq!(ok.pcrs.len(), 3);
        assert_eq!(ok.timestamp_ms, now() * 1000 - 1000);
        assert_eq!(ok.public_key.as_deref(), Some(&b"enclave-public-key"[..]));
        assert_eq!(ok.user_data.as_deref(), Some(&b"user"[..]));
        assert_eq!(ok.nonce.as_deref(), Some(&b"nonce-1"[..]));
        let pcr0_only = AttestationPolicy::pcr0(chain.root.clone(), [7u8; 48], MAX_AGE);
        assert!(verify_attestation(&doc, &pcr0_only, now()).is_ok());
    }

    #[test]
    fn a_leaf_issuer_first_bundle_is_rejected() {
        let chain = good_chain();
        let doc = seal(&chain, &[chain.intermediate.clone(), chain.root.clone()]);
        assert_eq!(
            verify_attestation(&doc, &policy(&chain), now()).unwrap_err(),
            NitroError::UntrustedRoot
        );
    }

    #[test]
    fn a_bundle_without_the_issuer_or_root_is_rejected() {
        let chain = good_chain();
        let root_only = seal(&chain, std::slice::from_ref(&chain.root));
        assert_eq!(
            verify_attestation(&root_only, &policy(&chain), now()).unwrap_err(),
            NitroError::BrokenChain
        );
        let empty = seal(&chain, &[]);
        assert_eq!(
            verify_attestation(&empty, &policy(&chain), now()).unwrap_err(),
            NitroError::UntrustedRoot
        );
    }

    #[test]
    fn an_expired_or_future_leaf_is_rejected() {
        for years in [(2020, 2021), (2030, 2031)] {
            let chain = chain_with(
                IsCa::Ca(Bc::Unconstrained),
                IsCa::Ca(Bc::Unconstrained),
                years,
            );
            assert_eq!(
                verify_attestation(&aws_document(&chain), &policy(&chain), now()).unwrap_err(),
                NitroError::CertificateNotValidNow
            );
        }
    }

    #[test]
    fn a_non_ca_intermediate_is_rejected() {
        for intermediate in [IsCa::ExplicitNoCa, IsCa::NoCa] {
            let chain = chain_with(IsCa::Ca(Bc::Unconstrained), intermediate, (2026, 2027));
            assert_eq!(
                verify_attestation(&aws_document(&chain), &policy(&chain), now()).unwrap_err(),
                NitroError::NotCa
            );
        }
    }

    #[test]
    fn a_path_length_constraint_is_honoured() {
        let chain = chain_with(
            IsCa::Ca(Bc::Constrained(0)),
            IsCa::Ca(Bc::Unconstrained),
            (2026, 2027),
        );
        assert_eq!(
            verify_attestation(&aws_document(&chain), &policy(&chain), now()).unwrap_err(),
            NitroError::PathLength
        );
        let chain = chain_with(
            IsCa::Ca(Bc::Constrained(1)),
            IsCa::Ca(Bc::Constrained(0)),
            (2026, 2027),
        );
        assert!(verify_attestation(&aws_document(&chain), &policy(&chain), now()).is_ok());
    }

    #[test]
    fn a_wrong_root_is_rejected() {
        let chain = good_chain();
        let other = good_chain();
        let doc = aws_document(&chain);
        let mut pinned_elsewhere = policy(&chain);
        pinned_elsewhere.root_der = other.root.clone();
        assert_eq!(
            verify_attestation(&doc, &pinned_elsewhere, now()).unwrap_err(),
            NitroError::UntrustedRoot
        );
        // A bundle that swaps in its own self-signed root is not trusted either.
        let swapped = seal(&chain, &[other.root.clone(), chain.intermediate.clone()]);
        assert_eq!(
            verify_attestation(&swapped, &policy(&chain), now()).unwrap_err(),
            NitroError::UntrustedRoot
        );
    }

    #[test]
    fn a_stale_or_future_timestamp_is_rejected() {
        let chain = good_chain();
        let bundle = [chain.root.clone(), chain.intermediate.clone()];
        for timestamp_ms in [
            (now() - MAX_AGE - 1) * 1000,
            now() * 1000 + MAX_FUTURE_SKEW_MS + 1,
        ] {
            let doc =
                seal_document(&chain.signing, &chain.leaf, &bundle, &fields(timestamp_ms)).unwrap();
            assert_eq!(
                verify_attestation(&doc, &policy(&chain), now()).unwrap_err(),
                NitroError::Stale
            );
        }
    }

    #[test]
    fn a_pcr_mismatch_is_rejected() {
        let chain = good_chain();
        let doc = aws_document(&chain);
        let mut wrong = policy(&chain);
        wrong.expected_pcrs.insert(2, [9u8; 48]);
        assert_eq!(
            verify_attestation(&doc, &wrong, now()).unwrap_err(),
            NitroError::PcrMismatch
        );
        let mut missing = policy(&chain);
        missing.expected_pcrs.insert(8, [0u8; 48]);
        assert_eq!(
            verify_attestation(&doc, &missing, now()).unwrap_err(),
            NitroError::PcrMismatch
        );
        let mut empty = policy(&chain);
        empty.expected_pcrs.clear();
        assert_eq!(
            verify_attestation(&doc, &empty, now()).unwrap_err(),
            NitroError::NoExpectedPcrs
        );
    }

    #[test]
    fn a_nonce_mismatch_is_rejected() {
        let chain = good_chain();
        let doc = aws_document(&chain);
        let mut wrong = policy(&chain);
        wrong.expected_nonce = Some(b"nonce-2".to_vec());
        assert_eq!(
            verify_attestation(&doc, &wrong, now()).unwrap_err(),
            NitroError::NonceMismatch
        );
        let bundle = [chain.root.clone(), chain.intermediate.clone()];
        let mut no_nonce = fields(now() * 1000);
        no_nonce.nonce = None;
        let doc = seal_document(&chain.signing, &chain.leaf, &bundle, &no_nonce).unwrap();
        assert_eq!(
            verify_attestation(&doc, &policy(&chain), now()).unwrap_err(),
            NitroError::NonceMismatch
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let chain = good_chain();
        let mut doc = aws_document(&chain);
        let last = doc.len() - 1;
        doc[last] ^= 0xff;
        assert_eq!(
            verify_attestation(&doc, &policy(&chain), now()).unwrap_err(),
            NitroError::BadSignature
        );
    }

    #[test]
    fn certificate_times_parse_in_both_forms() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(
            parse_time(0x17, b"260601000000Z").unwrap(),
            days_from_civil(2026, 6, 1) * 86_400
        );
        assert_eq!(
            parse_time(0x18, b"20500101000001Z").unwrap(),
            days_from_civil(2050, 1, 1) * 86_400 + 1
        );
        assert_eq!(
            parse_time(0x17, b"500101000000Z").unwrap(),
            days_from_civil(1950, 1, 1) * 86_400
        );
        assert!(parse_time(0x17, b"261301000000Z").is_err());
        assert!(parse_time(0x18, b"260601000000Z").is_err());
    }
}
