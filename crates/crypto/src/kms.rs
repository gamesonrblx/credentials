//! Root-key providers.
//!
//! A production deployment uses a cloud KMS or an HSM behind [`RootKeyProvider`].
//! This crate ships two providers that hold root keys outside a KMS so tests
//! and a laptop can run. Both refuse to construct when the caller passes a
//! [`DevPolicy`] that disallows dev keys, which is what
//! `CREDENTIALS_ENV=production` produces. The dev file stores raw 32-byte root
//! keys. Do not point it at a production disk.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::aead::{open, seal};
use crate::random::random_array;
use crate::CryptoError;

/// The four encryption-context fields from the spec. One builder, used by
/// every encrypt and decrypt, so the map cannot drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KekContext {
    pub workspace_id: Uuid,
    pub kek_id: Uuid,
    pub kek_version: u32,
}

impl KekContext {
    pub const PURPOSE: &'static str = "credentials.kek.v1";

    pub fn pairs(&self) -> [(&'static str, String); 4] {
        [
            ("kek_id", self.kek_id.to_string()),
            ("kek_version", self.kek_version.to_string()),
            ("purpose", Self::PURPOSE.to_owned()),
            ("workspace_id", self.workspace_id.to_string()),
        ]
    }
}

/// Wraps tenant KEKs. The root key itself never appears in the database.
pub trait RootKeyProvider: Send + Sync {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError>;
    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        context: &KekContext,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
    fn schedule_destruction(&self, key_ref: &str, not_before_unix: u64) -> Result<(), CryptoError>;
    fn cancel_destruction(&self, key_ref: &str) -> Result<(), CryptoError>;
    fn root_key_state(&self, key_ref: &str) -> Result<RootKeyState, CryptoError>;
    /// When `now_unix` is at or past a pending destruction time, the key becomes
    /// destroyed and later cancel calls fail.
    fn destroy_if_due(&self, key_ref: &str, now_unix: u64) -> Result<bool, CryptoError>;
}

/// What the provider reports for a tenant root. The gateway compares
/// `not_before_unix` with its own clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootKeyState {
    Active,
    Pending { not_before_unix: u64 },
    Destroyed,
}

/// How the process decides whether a dev provider may exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevPolicy {
    pub allow_dev: bool,
}

impl DevPolicy {
    /// An unset variable means development. `production` or `prod` selects
    /// the control plane. `development`, `dev`, and `test` select dev. Case
    /// and surrounding whitespace are ignored. Any other value, including an
    /// empty one, is an error, so a typo cannot start a dev gateway.
    pub fn from_env_value(value: Option<&str>) -> Result<Self, CryptoError> {
        let Some(raw) = value else {
            return Ok(Self { allow_dev: true });
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" => Ok(Self { allow_dev: false }),
            "development" | "dev" | "test" => Ok(Self { allow_dev: true }),
            _ => Err(CryptoError::UnknownEnvironment),
        }
    }

    /// Reads `CREDENTIALS_ENV`. A value that is not valid Unicode is an error.
    pub fn from_env() -> Result<Self, CryptoError> {
        match std::env::var("CREDENTIALS_ENV") {
            Ok(value) => Self::from_env_value(Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::from_env_value(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(CryptoError::UnknownEnvironment),
        }
    }

    fn check(self) -> Result<(), CryptoError> {
        if self.allow_dev {
            Ok(())
        } else {
            Err(CryptoError::DevProviderInProduction)
        }
    }
}

#[derive(Clone, Debug)]
enum KeyLife {
    Active,
    Pending { not_before_unix: u64 },
    Destroyed,
}

struct TenantRoot {
    key: Zeroizing<[u8; 32]>,
    life: KeyLife,
}

/// In-memory roots for unit tests. Same refusal rule as the file provider.
pub struct MemoryRootKeys {
    keys: Mutex<BTreeMap<String, TenantRoot>>,
}

impl MemoryRootKeys {
    pub fn new(policy: DevPolicy) -> Result<Self, CryptoError> {
        policy.check()?;
        Ok(Self {
            keys: Mutex::new(BTreeMap::new()),
        })
    }
}

impl RootKeyProvider for MemoryRootKeys {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        let key_ref = format!("memory:{workspace_id}");
        let root = TenantRoot {
            key: Zeroizing::new(random_array()?),
            life: KeyLife::Active,
        };
        self.keys
            .lock()
            .expect("memory root lock")
            .insert(key_ref.clone(), root);
        Ok(key_ref)
    }

    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        let keys = self.keys.lock().expect("memory root lock");
        let root = usable_root(keys.get(key_ref), now_unix())?;
        seal_under_root(root, plaintext, context)
    }

    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        context: &KekContext,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let keys = self.keys.lock().expect("memory root lock");
        let root = usable_root(keys.get(key_ref), now_unix())?;
        open_under_root(root, blob, context)
    }

    fn schedule_destruction(&self, key_ref: &str, not_before_unix: u64) -> Result<(), CryptoError> {
        let mut keys = self.keys.lock().expect("memory root lock");
        let root = keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        root.life = KeyLife::Pending { not_before_unix };
        Ok(())
    }

    fn cancel_destruction(&self, key_ref: &str) -> Result<(), CryptoError> {
        let mut keys = self.keys.lock().expect("memory root lock");
        let root = keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        if matches!(root.life, KeyLife::Destroyed) {
            return Err(CryptoError::RootKeyUnavailable);
        }
        root.life = KeyLife::Active;
        Ok(())
    }

    fn root_key_state(&self, key_ref: &str) -> Result<RootKeyState, CryptoError> {
        let keys = self.keys.lock().expect("memory root lock");
        let root = keys.get(key_ref).ok_or(CryptoError::RootKeyUnavailable)?;
        Ok(match root.life {
            KeyLife::Active => RootKeyState::Active,
            KeyLife::Pending { not_before_unix } => RootKeyState::Pending { not_before_unix },
            KeyLife::Destroyed => RootKeyState::Destroyed,
        })
    }

    fn destroy_if_due(&self, key_ref: &str, now_unix: u64) -> Result<bool, CryptoError> {
        let mut keys = self.keys.lock().expect("memory root lock");
        let root = keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        match root.life {
            KeyLife::Destroyed => Ok(true),
            KeyLife::Pending { not_before_unix } if now_unix >= not_before_unix => {
                root.life = KeyLife::Destroyed;
                Ok(true)
            }
            KeyLife::Pending { .. } | KeyLife::Active => Ok(false),
        }
    }
}

/// File-backed dev provider. The on-disk bytes are raw root keys.
///
/// Not for production. `DevPolicy` enforces that at construction.
pub struct DevFileRootKeys {
    path: PathBuf,
    inner: Mutex<()>,
}

impl DevFileRootKeys {
    pub fn open(path: impl Into<PathBuf>, policy: DevPolicy) -> Result<Self, CryptoError> {
        policy.check()?;
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| CryptoError::Io)?;
            }
        }
        if !path.exists() {
            write_file(&path, &FileStore::default())?;
        }
        Ok(Self {
            path,
            inner: Mutex::new(()),
        })
    }
}

impl RootKeyProvider for DevFileRootKeys {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let mut store = read_file(&self.path)?;
        let key_ref = format!("file:{workspace_id}");
        let key = random_array::<32>()?;
        store.keys.insert(
            key_ref.clone(),
            FileKey {
                root_hex: hex_encode(&key),
                state: "active".to_owned(),
                not_before_unix: None,
            },
        );
        write_file(&self.path, &store)?;
        Ok(key_ref)
    }

    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let store = read_file(&self.path)?;
        let root = file_root(&store, key_ref, now_unix())?;
        seal_under_root(&root, plaintext, context)
    }

    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        context: &KekContext,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let store = read_file(&self.path)?;
        let root = file_root(&store, key_ref, now_unix())?;
        open_under_root(&root, blob, context)
    }

    fn schedule_destruction(&self, key_ref: &str, not_before_unix: u64) -> Result<(), CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let mut store = read_file(&self.path)?;
        let key = store
            .keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        key.state = "pending".to_owned();
        key.not_before_unix = Some(not_before_unix);
        write_file(&self.path, &store)
    }

    fn cancel_destruction(&self, key_ref: &str) -> Result<(), CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let mut store = read_file(&self.path)?;
        let key = store
            .keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        if key.state == "destroyed" {
            return Err(CryptoError::RootKeyUnavailable);
        }
        key.state = "active".to_owned();
        key.not_before_unix = None;
        write_file(&self.path, &store)
    }

    fn root_key_state(&self, key_ref: &str) -> Result<RootKeyState, CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let store = read_file(&self.path)?;
        let key = store
            .keys
            .get(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        Ok(match key.state.as_str() {
            "active" => RootKeyState::Active,
            "pending" => RootKeyState::Pending {
                not_before_unix: key.not_before_unix.unwrap_or(0),
            },
            "destroyed" => RootKeyState::Destroyed,
            _ => return Err(CryptoError::CorruptStore),
        })
    }

    fn destroy_if_due(&self, key_ref: &str, now_unix: u64) -> Result<bool, CryptoError> {
        let _guard = self.inner.lock().expect("dev file lock");
        let mut store = read_file(&self.path)?;
        let key = store
            .keys
            .get_mut(key_ref)
            .ok_or(CryptoError::RootKeyUnavailable)?;
        let due = match key.state.as_str() {
            "destroyed" => true,
            "pending" => now_unix >= key.not_before_unix.unwrap_or(0),
            "active" => false,
            _ => return Err(CryptoError::CorruptStore),
        };
        if due {
            key.state = "destroyed".to_owned();
            write_file(&self.path, &store)?;
        }
        Ok(due)
    }
}

/// A root-key provider that cannot wrap or unwrap anything.
///
/// The production control plane uses this so a configuration mistake cannot
/// become a decrypt path. Every method fails.
pub struct RejectingRootKeys;

impl RootKeyProvider for RejectingRootKeys {
    fn create_tenant_root(&self, _workspace_id: Uuid) -> Result<String, CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn encrypt(
        &self,
        _key_ref: &str,
        _plaintext: &[u8],
        _context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn decrypt(
        &self,
        _key_ref: &str,
        _blob: &[u8],
        _context: &KekContext,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn schedule_destruction(
        &self,
        _key_ref: &str,
        _not_before_unix: u64,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn cancel_destruction(&self, _key_ref: &str) -> Result<(), CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn root_key_state(&self, _key_ref: &str) -> Result<RootKeyState, CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }

    fn destroy_if_due(&self, _key_ref: &str, _now_unix: u64) -> Result<bool, CryptoError> {
        Err(CryptoError::DevProviderInProduction)
    }
}

/// Counts `decrypt` calls. Used to prove a denied request never unwraps a key.
pub struct CountingProvider<P> {
    inner: P,
    decrypts: AtomicU64,
}

impl<P> CountingProvider<P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            decrypts: AtomicU64::new(0),
        }
    }

    pub fn decrypts(&self) -> u64 {
        self.decrypts.load(Ordering::Relaxed)
    }
}

impl<P: RootKeyProvider> RootKeyProvider for CountingProvider<P> {
    fn create_tenant_root(&self, workspace_id: Uuid) -> Result<String, CryptoError> {
        self.inner.create_tenant_root(workspace_id)
    }

    fn encrypt(
        &self,
        key_ref: &str,
        plaintext: &[u8],
        context: &KekContext,
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.encrypt(key_ref, plaintext, context)
    }

    fn decrypt(
        &self,
        key_ref: &str,
        blob: &[u8],
        context: &KekContext,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.decrypts.fetch_add(1, Ordering::Relaxed);
        self.inner.decrypt(key_ref, blob, context)
    }

    fn schedule_destruction(&self, key_ref: &str, not_before_unix: u64) -> Result<(), CryptoError> {
        self.inner.schedule_destruction(key_ref, not_before_unix)
    }

    fn cancel_destruction(&self, key_ref: &str) -> Result<(), CryptoError> {
        self.inner.cancel_destruction(key_ref)
    }

    fn root_key_state(&self, key_ref: &str) -> Result<RootKeyState, CryptoError> {
        self.inner.root_key_state(key_ref)
    }

    fn destroy_if_due(&self, key_ref: &str, now_unix: u64) -> Result<bool, CryptoError> {
        self.inner.destroy_if_due(key_ref, now_unix)
    }
}

fn usable_root(root: Option<&TenantRoot>, now: u64) -> Result<&[u8; 32], CryptoError> {
    let root = root.ok_or(CryptoError::RootKeyUnavailable)?;
    match root.life {
        KeyLife::Active => Ok(&root.key),
        KeyLife::Pending { not_before_unix } if now < not_before_unix => Ok(&root.key),
        KeyLife::Pending { .. } | KeyLife::Destroyed => Err(CryptoError::RootKeyUnavailable),
    }
}

fn seal_under_root(
    root: &[u8; 32],
    plaintext: &[u8],
    context: &KekContext,
) -> Result<Vec<u8>, CryptoError> {
    let nonce: [u8; 12] = random_array()?;
    let aad = context_aad(context);
    let ciphertext = seal(root, &nonce, plaintext, &aad)?;
    let mut blob = Vec::with_capacity(4 + 12 + ciphertext.len());
    blob.extend_from_slice(b"DEV1");
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn open_under_root(
    root: &[u8; 32],
    blob: &[u8],
    context: &KekContext,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.len() < 4 + 12 || &blob[..4] != b"DEV1" {
        return Err(CryptoError::Decrypt);
    }
    let nonce = &blob[4..16];
    let ciphertext = &blob[16..];
    let aad = context_aad(context);
    open(root, nonce, ciphertext, &aad)
}

fn context_aad(context: &KekContext) -> Vec<u8> {
    let mut pairs = context.pairs();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (key, value) in pairs {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();
        out.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(key_bytes);
        out.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(value_bytes);
    }
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileStore {
    warning: String,
    keys: BTreeMap<String, FileKey>,
}

impl Default for FileStore {
    fn default() -> Self {
        Self {
            warning: "DEV ONLY. Not for production. This file contains raw root keys.".to_owned(),
            keys: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileKey {
    root_hex: String,
    state: String,
    not_before_unix: Option<u64>,
}

fn file_root(store: &FileStore, key_ref: &str, now: u64) -> Result<[u8; 32], CryptoError> {
    let key = store
        .keys
        .get(key_ref)
        .ok_or(CryptoError::RootKeyUnavailable)?;
    match key.state.as_str() {
        "active" => {}
        "pending" => {
            let not_before = key.not_before_unix.unwrap_or(0);
            if now >= not_before {
                return Err(CryptoError::RootKeyUnavailable);
            }
        }
        _ => return Err(CryptoError::RootKeyUnavailable),
    }
    let bytes = hex_decode(&key.root_hex).map_err(|_| CryptoError::CorruptStore)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::CorruptStore)?;
    Ok(array)
}

fn read_file(path: &Path) -> Result<FileStore, CryptoError> {
    let bytes = fs::read(path).map_err(|_| CryptoError::Io)?;
    serde_json::from_slice(&bytes).map_err(|_| CryptoError::CorruptStore)
}

fn write_file(path: &Path, store: &FileStore) -> Result<(), CryptoError> {
    let bytes = serde_json::to_vec_pretty(store).map_err(|_| CryptoError::CorruptStore)?;
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|_| CryptoError::Io)?;
        file.write_all(&bytes).map_err(|_| CryptoError::Io)?;
        file.sync_all().map_err(|_| CryptoError::Io)?;
    }
    fs::rename(&tmp, path).map_err(|_| CryptoError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_ok() -> DevPolicy {
        DevPolicy { allow_dev: true }
    }

    #[test]
    fn production_policy_refuses_dev_providers() {
        let denied = DevPolicy::from_env_value(Some("production")).unwrap();
        assert!(MemoryRootKeys::new(denied).is_err());
        let dir = std::env::temp_dir().join(format!("credentials-dev-refuse-{}", Uuid::now_v7()));
        let path = dir.join("keys.json");
        assert!(DevFileRootKeys::open(&path, denied).is_err());
    }

    #[test]
    fn environment_value_fails_closed_on_anything_unrecognised() {
        for value in ["production", "Production", " PROD\n", "prod"] {
            assert!(!DevPolicy::from_env_value(Some(value)).unwrap().allow_dev);
        }
        for value in ["development", "dev", "Test"] {
            assert!(DevPolicy::from_env_value(Some(value)).unwrap().allow_dev);
        }
        assert!(DevPolicy::from_env_value(None).unwrap().allow_dev);
        for value in ["", "  ", "producton", "staging", "live", "production1"] {
            assert!(matches!(
                DevPolicy::from_env_value(Some(value)),
                Err(CryptoError::UnknownEnvironment)
            ));
        }
    }

    #[test]
    fn memory_round_trip_context_and_destruction() {
        let kms = MemoryRootKeys::new(policy_ok()).unwrap();
        let workspace = Uuid::now_v7();
        let key_ref = kms.create_tenant_root(workspace).unwrap();
        let context = KekContext {
            workspace_id: workspace,
            kek_id: Uuid::now_v7(),
            kek_version: 1,
        };
        let blob = kms
            .encrypt(&key_ref, b"thirty-two-byte-key-material!!", &context)
            .unwrap();
        let opened = kms.decrypt(&key_ref, &blob, &context).unwrap();
        assert_eq!(opened.as_slice(), b"thirty-two-byte-key-material!!");

        let wrong = KekContext {
            kek_version: 2,
            ..context.clone()
        };
        assert!(kms.decrypt(&key_ref, &blob, &wrong).is_err());

        let future = now_unix().saturating_add(86_400);
        kms.schedule_destruction(&key_ref, future).unwrap();
        assert!(kms.decrypt(&key_ref, &blob, &context).is_ok());
        kms.schedule_destruction(&key_ref, 0).unwrap();
        assert!(matches!(
            kms.decrypt(&key_ref, &blob, &context),
            Err(CryptoError::RootKeyUnavailable)
        ));
        kms.cancel_destruction(&key_ref).unwrap();
        assert!(kms.decrypt(&key_ref, &blob, &context).is_ok());
    }

    #[test]
    fn dev_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("credentials-dev-{}", Uuid::now_v7()));
        let path = dir.join("keys.json");
        let kms = DevFileRootKeys::open(&path, policy_ok()).unwrap();
        let workspace = Uuid::now_v7();
        let key_ref = kms.create_tenant_root(workspace).unwrap();
        let context = KekContext {
            workspace_id: workspace,
            kek_id: Uuid::now_v7(),
            kek_version: 3,
        };
        let blob = kms.encrypt(&key_ref, &[7u8; 32], &context).unwrap();
        let opened = kms.decrypt(&key_ref, &blob, &context).unwrap();
        assert_eq!(opened.as_slice(), &[7u8; 32]);
        let _ = fs::remove_dir_all(dir);
    }
}
