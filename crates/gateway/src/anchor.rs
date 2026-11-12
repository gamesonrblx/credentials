//! External audit anchor.
//!
//! The hash chain in the database is not enough on its own. A checkpoint
//! signature is copied to an anchor the database role cannot rewrite. The dev
//! file is refused when `CREDENTIALS_ENV=production`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use credentials_crypto::DevPolicy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ApiError;

pub const CHECKPOINT_PREFIX: &[u8] = b"credentials.audit.checkpoint.v1\n";
pub const CHECKPOINT_EVERY_EVENTS: u64 = 1_000;
pub const CHECKPOINT_EVERY_SECS: u64 = 60;
pub const AUDIT_ANCHOR_MAX_LAG: u64 = 15 * 60;

pub fn checkpoint_message(workspace_id: Uuid, seq: u64, tip_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(CHECKPOINT_PREFIX.len() + 16 + 8 + 32);
    message.extend_from_slice(CHECKPOINT_PREFIX);
    message.extend_from_slice(workspace_id.as_bytes());
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(tip_hash);
    message
}

#[derive(Clone, Debug)]
pub struct AnchoredTip {
    pub seq: u64,
    pub tip_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[async_trait]
pub trait AuditAnchor: Send + Sync {
    async fn put(
        &self,
        workspace_id: Uuid,
        seq: u64,
        tip_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ApiError>;
    async fn latest(&self, workspace_id: Uuid) -> Result<Option<AnchoredTip>, ApiError>;
}

/// In-memory anchor for unit tests. `fail` makes `put` return an error.
pub struct MemoryAnchor {
    fail: AtomicBool,
    tips: Mutex<Vec<(Uuid, AnchoredTip)>>,
}

impl MemoryAnchor {
    pub fn new() -> Self {
        Self {
            fail: AtomicBool::new(false),
            tips: Mutex::new(Vec::new()),
        }
    }

    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::Relaxed);
    }
}

impl Default for MemoryAnchor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditAnchor for MemoryAnchor {
    async fn put(
        &self,
        workspace_id: Uuid,
        seq: u64,
        tip_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ApiError> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(ApiError::AuditAnchorUnavailable);
        }
        self.tips.lock().expect("anchor lock").push((
            workspace_id,
            AnchoredTip {
                seq,
                tip_hash: *tip_hash,
                signature: signature.to_vec(),
            },
        ));
        Ok(())
    }

    async fn latest(&self, workspace_id: Uuid) -> Result<Option<AnchoredTip>, ApiError> {
        Ok(self
            .tips
            .lock()
            .expect("anchor lock")
            .iter()
            .rev()
            .find(|(id, _)| *id == workspace_id)
            .map(|(_, tip)| tip.clone()))
    }
}

/// Append-only local file. Allowed in production. Not a retention-locked
/// object store, and not the dev anchor.
pub struct FileAnchor {
    path: PathBuf,
}

impl FileAnchor {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ApiError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|_| ApiError::StoreUnavailable)?;
            }
        }
        if !path.exists() {
            write_exclusive(&path, b"")?;
        }
        Ok(Self { path })
    }
}

/// Dev file anchor. Refused when `CREDENTIALS_ENV=production`.
pub struct DevFileAnchor {
    inner: FileAnchor,
}

impl DevFileAnchor {
    pub fn open(path: impl Into<PathBuf>, policy: DevPolicy) -> Result<Self, ApiError> {
        if !policy.allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
        Ok(Self {
            inner: FileAnchor::open(path)?,
        })
    }
}

#[async_trait]
impl AuditAnchor for FileAnchor {
    async fn put(
        &self,
        workspace_id: Uuid,
        seq: u64,
        tip_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ApiError> {
        let line = serde_json::to_vec(&FileTip {
            workspace_id,
            seq,
            tip_hash_hex: hex_encode(tip_hash),
            signature_hex: hex_encode(signature),
        })
        .map_err(|_| ApiError::StoreUnavailable)?;
        let mut bytes = line;
        bytes.push(b'\n');
        append_exclusive(&self.path, &bytes)
    }

    async fn latest(&self, workspace_id: Uuid) -> Result<Option<AnchoredTip>, ApiError> {
        let bytes = fs::read(&self.path).map_err(|_| ApiError::StoreUnavailable)?;
        let text = String::from_utf8_lossy(&bytes);
        let mut found = None;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let tip: FileTip =
                serde_json::from_str(line).map_err(|_| ApiError::StoreUnavailable)?;
            if tip.workspace_id != workspace_id {
                continue;
            }
            found = Some(AnchoredTip {
                seq: tip.seq,
                tip_hash: hex32(&tip.tip_hash_hex)?,
                signature: hex_decode(&tip.signature_hex)
                    .map_err(|_| ApiError::StoreUnavailable)?,
            });
        }
        Ok(found)
    }
}

#[async_trait]
impl AuditAnchor for DevFileAnchor {
    async fn put(
        &self,
        workspace_id: Uuid,
        seq: u64,
        tip_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), ApiError> {
        self.inner.put(workspace_id, seq, tip_hash, signature).await
    }

    async fn latest(&self, workspace_id: Uuid) -> Result<Option<AnchoredTip>, ApiError> {
        self.inner.latest(workspace_id).await
    }
}

#[derive(Serialize, Deserialize)]
struct FileTip {
    workspace_id: Uuid,
    seq: u64,
    tip_hash_hex: String,
    signature_hex: String,
}

/// Create the anchor file if it is missing. An existing file is never
/// truncated, so a startup race cannot drop anchored lines.
fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(_) => return Err(ApiError::StoreUnavailable),
    };
    file.write_all(bytes)
        .map_err(|_| ApiError::StoreUnavailable)?;
    file.sync_all().map_err(|_| ApiError::StoreUnavailable)?;
    sync_parent(path);
    Ok(())
}

/// Append one line and fsync before `put` reports success. The file is
/// append-only and never rewritten, so no tmp-and-rename step is needed.
fn append_exclusive(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| ApiError::StoreUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| ApiError::StoreUnavailable)?;
    file.sync_all().map_err(|_| ApiError::StoreUnavailable)?;
    Ok(())
}

/// Make a newly created file's directory entry durable. Unix only; Windows
/// cannot open a directory for sync.
fn sync_parent(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
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

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn hex32(value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex_decode(value).map_err(|_| ApiError::StoreUnavailable)?;
    bytes.try_into().map_err(|_| ApiError::StoreUnavailable)
}
