//! Account-bound wraps of the workspace decapsulation key.
//!
//! Every wrap is produced by a holder of that key. There is no function that
//! wraps to an operator, a KMS key, or a login secret. Losing every recipient
//! loses the workspace key.

use zeroize::Zeroizing;

use crate::aead::{open, seal};
use crate::hybrid::{unwrap_key_with_aad, wrap_key_with_aad, HybridWrapped};
use crate::random::random_array;
use crate::CryptoError;
use uuid::Uuid;

/// RFC 9106's second recommended memory and time cost. Parallelism is 1 so a
/// single-CPU self-host does not oversubscribe. Tests pass a smaller
/// [`KitParams`] and must not claim those parameters are the production ones.
pub const KIT_MEMORY_KIB: u32 = 65_536;
pub const KIT_TIME_COST: u32 = 3;
pub const KIT_PARALLELISM: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KitParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt: [u8; 16],
}

impl KitParams {
    pub fn production(salt: [u8; 16]) -> Self {
        Self {
            memory_kib: KIT_MEMORY_KIB,
            time_cost: KIT_TIME_COST,
            parallelism: KIT_PARALLELISM,
            salt,
        }
    }

    /// Fast parameters for tests. Not a production default.
    pub fn test(salt: [u8; 16]) -> Self {
        Self {
            memory_kib: 8,
            time_cost: 1,
            parallelism: 1,
            salt,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymmetricWrap {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn seal_to_device(
    encapsulation_key: &[u8],
    workspace_id: Uuid,
    workspace_key: &[u8; 32],
) -> Result<HybridWrapped, CryptoError> {
    wrap_key_with_aad(encapsulation_key, workspace_key, &device_aad(workspace_id))
}

pub fn open_from_device(
    decapsulation_key: &[u8; 32],
    workspace_id: Uuid,
    wrapped: &HybridWrapped,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    unwrap_key_with_aad(decapsulation_key, wrapped, &device_aad(workspace_id))
}

pub fn seal_to_passkey(
    prf_output: &[u8; 32],
    salt: &[u8],
    workspace_id: Uuid,
    workspace_key: &[u8; 32],
) -> Result<SymmetricWrap, CryptoError> {
    if salt.is_empty() || salt.len() > 64 {
        return Err(CryptoError::KeyLength);
    }
    let nonce: [u8; 12] = random_array()?;
    let ciphertext = seal(
        prf_output,
        &nonce,
        workspace_key,
        &passkey_aad(workspace_id, salt),
    )?;
    Ok(SymmetricWrap { nonce, ciphertext })
}

pub fn open_from_passkey(
    prf_output: &[u8; 32],
    salt: &[u8],
    workspace_id: Uuid,
    wrapped: &SymmetricWrap,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let plain = open(
        prf_output,
        &wrapped.nonce,
        &wrapped.ciphertext,
        &passkey_aad(workspace_id, salt),
    )?;
    key32(plain)
}

pub fn seal_recovery_kit(
    secret: &[u8],
    workspace_id: Uuid,
    workspace_key: &[u8; 32],
    params: &KitParams,
) -> Result<SymmetricWrap, CryptoError> {
    if secret.len() < 16 {
        return Err(CryptoError::KeyLength);
    }
    let derived = derive_kit_key(secret, params)?;
    let nonce: [u8; 12] = random_array()?;
    let ciphertext = seal(
        &derived,
        &nonce,
        workspace_key,
        &kit_aad(workspace_id, params),
    )?;
    Ok(SymmetricWrap { nonce, ciphertext })
}

pub fn open_recovery_kit(
    secret: &[u8],
    workspace_id: Uuid,
    wrapped: &SymmetricWrap,
    params: &KitParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let derived = derive_kit_key(secret, params)?;
    let plain = open(
        &derived,
        &wrapped.nonce,
        &wrapped.ciphertext,
        &kit_aad(workspace_id, params),
    )?;
    key32(plain)
}

pub fn derive_kit_key(secret: &[u8], params: &KitParams) -> Result<[u8; 32], CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let built = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        None,
    )
    .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, built);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(secret, &params.salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

fn device_aad(workspace_id: Uuid) -> Vec<u8> {
    let mut aad = b"credentials.workspace.key.v1".to_vec();
    aad.extend_from_slice(workspace_id.as_bytes());
    aad
}

fn passkey_aad(workspace_id: Uuid, salt: &[u8]) -> Vec<u8> {
    let mut aad = b"credentials.recovery.prf.v1".to_vec();
    aad.extend_from_slice(workspace_id.as_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn kit_aad(workspace_id: Uuid, params: &KitParams) -> Vec<u8> {
    let mut aad = b"credentials.recovery.kit.v1".to_vec();
    aad.extend_from_slice(workspace_id.as_bytes());
    aad.extend_from_slice(&params.memory_kib.to_be_bytes());
    aad.extend_from_slice(&params.time_cost.to_be_bytes());
    aad.extend_from_slice(&params.parallelism.to_be_bytes());
    aad.extend_from_slice(&params.salt);
    aad
}

fn key32(plain: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if plain.len() != 32 {
        return Err(CryptoError::KeyLength);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plain);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::generate_hybrid_keypair;

    #[test]
    fn a_second_device_a_passkey_and_a_kit_open_the_same_workspace_key() {
        let workspace_id = Uuid::now_v7();
        let workspace = generate_hybrid_keypair().unwrap();
        let workspace_key = *workspace.decapsulation_key();
        let device = generate_hybrid_keypair().unwrap();
        let device_wrap =
            seal_to_device(&device.encapsulation_key, workspace_id, &workspace_key).unwrap();
        let opened =
            open_from_device(device.decapsulation_key(), workspace_id, &device_wrap).unwrap();
        assert_eq!(opened.as_slice(), workspace_key.as_slice());

        let prf = [7u8; 32];
        let salt = b"prf-salt";
        let passkey = seal_to_passkey(&prf, salt, workspace_id, &workspace_key).unwrap();
        let from_prf = open_from_passkey(&prf, salt, workspace_id, &passkey).unwrap();
        assert_eq!(from_prf.as_slice(), workspace_key.as_slice());
        assert!(open_from_passkey(&[8u8; 32], salt, workspace_id, &passkey).is_err());

        let params = KitParams::test([9u8; 16]);
        let secret = b"recovery-kit-secret";
        let kit = seal_recovery_kit(secret, workspace_id, &workspace_key, &params).unwrap();
        let from_kit = open_recovery_kit(secret, workspace_id, &kit, &params).unwrap();
        assert_eq!(from_kit.as_slice(), workspace_key.as_slice());
        assert!(open_recovery_kit(b"wrong-kit-secret!", workspace_id, &kit, &params).is_err());
    }

    #[test]
    fn production_kit_parameters_match_the_chosen_rfc9106_defaults() {
        let params = KitParams::production([0u8; 16]);
        assert_eq!(params.memory_kib, 65_536);
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 1);
    }
}
