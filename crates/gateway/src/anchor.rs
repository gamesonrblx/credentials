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

/// Append-only local file. Not a retention-locked object store.
pub struct DevFileAnchor {
    path: PathBuf,
}

impl DevFileAnchor {
    pub fn open(path: impl Into<PathBuf>, policy: DevPolicy) -> Result<Self, ApiError> {
        if !policy.allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
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

#[async_trait]
impl AuditAnchor for DevFileAnchor {
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

#[derive(Serialize, Deserialize)]
struct FileTip {
    workspace_id: Uuid,
    seq: u64,
    tip_hash_hex: String,
    signature_hex: String,
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), ApiError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| ApiError::StoreUnavailable)?;
    file.write_all(bytes)
        .map_err(|_| ApiError::StoreUnavailable)?;
    Ok(())
}

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
