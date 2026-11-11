use crate::CryptoError;

/// Fill `buf` from the operating system CSPRNG (`getrandom`).
pub fn random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    random_bytes(&mut buf)?;
    Ok(buf)
}
