//! Store seam for the gateway.
//!
//! [`MemoryStore`] backs unit tests. [`crate::sql_store::SqlStore`] is the
//! durable adapter for SQLite (local and CI on every OS) and Postgres
//! (production, and the Ubuntu CI job). Audit append and the rows it records
//! share one critical section, so a failed append does not leave a
//! half-written access.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use credentials_crypto::SealedSecret;
use uuid::Uuid;

use crate::audit::{commit_event, AuditDraft, AuditRecord};
use crate::policy::DeliveryPolicy;
use crate::ApiError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WrapMode {
    Gateway,
    /// Reserved for M3. Writers reject it. The column exists so a later mode
    /// does not rewrite the meaning of gateway rows.
    E2e,
}

impl WrapMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::E2e => "e2e",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "gateway" => Ok(Self::Gateway),
            "e2e" => Ok(Self::E2e),
            _ => Err(ApiError::DecryptFailed),
        }
    }
}

/// Gateway-wrapped rows are the only ones this build can open.
pub fn ensure_gateway(mode: WrapMode, encapsulation: Option<&[u8]>) -> Result<(), ApiError> {
    if mode == WrapMode::Gateway && encapsulation.is_none() {
        Ok(())
    } else {
        Err(ApiError::BadRequest)
    }
}

#[derive(Clone, Debug)]
pub struct WorkspaceRow {
    pub id: Uuid,
    pub status: String,
    pub kms_key_ref: String,
    pub credential_hash: [u8; 32],
    pub audit_seq: u64,
}

#[derive(Clone, Debug)]
pub struct KekRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub version: u32,
    pub status: String,
    pub wrapped_kek: Vec<u8>,
    pub kms_key_ref: String,
}

#[derive(Clone, Debug)]
pub struct SecretRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub name: String,
    pub status: String,
    pub policy: DeliveryPolicy,
}

#[derive(Clone, Debug)]
pub struct VersionRow {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub workspace_id: Uuid,
    pub version: u32,
    pub sealed: SealedSecret,
    pub kek_id: Uuid,
    pub wrap_mode: WrapMode,
    pub e2e_encapsulation: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct AgentRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub display_name: String,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub agent_id: Uuid,
    pub dpop_jkt: String,
    pub scopes: Vec<String>,
    pub expires_at: u64,
    pub revoked_at: Option<u64>,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn insert_workspace(&self, row: WorkspaceRow, kek: KekRow) -> Result<(), ApiError>;
    async fn workspace_by_hash(&self, hash: &[u8; 32]) -> Result<WorkspaceRow, ApiError>;
    async fn workspace(&self, id: Uuid) -> Result<WorkspaceRow, ApiError>;
    async fn set_workspace_status(&self, id: Uuid, status: &str) -> Result<(), ApiError>;
    async fn insert_kek(&self, kek: KekRow) -> Result<(), ApiError>;
    /// Retire the current active KEK and insert the next active row in one step.
    /// A partial unique index allows only one active KEK, so the two writes
    /// cannot be separate commits.
    async fn swap_active_kek(&self, old_id: Uuid, new_kek: KekRow) -> Result<(), ApiError>;
    async fn active_kek(&self, workspace_id: Uuid) -> Result<KekRow, ApiError>;
    async fn kek(&self, id: Uuid) -> Result<KekRow, ApiError>;
    async fn list_keks(&self, workspace_id: Uuid) -> Result<Vec<KekRow>, ApiError>;
    async fn set_kek_status(&self, id: Uuid, status: &str) -> Result<(), ApiError>;
    async fn next_kek_version(&self, workspace_id: Uuid) -> Result<u32, ApiError>;
    async fn insert_agent(&self, row: AgentRow) -> Result<(), ApiError>;
    async fn agent(&self, id: Uuid) -> Result<AgentRow, ApiError>;
    async fn insert_session(&self, row: SessionRow) -> Result<(), ApiError>;
    async fn session(&self, id: Uuid) -> Result<SessionRow, ApiError>;
    async fn revoke_session(&self, id: Uuid, at: u64) -> Result<(), ApiError>;
    async fn insert_secret(
        &self,
        secret: SecretRow,
        version: VersionRow,
        audit: AuditDraft,
    ) -> Result<(), ApiError>;
    async fn insert_version(&self, version: VersionRow, audit: AuditDraft) -> Result<(), ApiError>;
    async fn secret_by_name(&self, workspace_id: Uuid, name: &str) -> Result<SecretRow, ApiError>;
    async fn latest_version(&self, secret_id: Uuid) -> Result<VersionRow, ApiError>;
    async fn versions_for_kek(&self, kek_id: Uuid) -> Result<Vec<VersionRow>, ApiError>;
    /// Replace the data-key wrap only when the row still names `expected_kek`.
    /// Payload columns stay as they are. `false` means another writer already
    /// moved the row.
    async fn update_wrap(
        &self,
        version_id: Uuid,
        expected_kek: Uuid,
        sealed: SealedSecret,
        new_kek: Uuid,
    ) -> Result<bool, ApiError>;
    async fn append_audit(&self, draft: AuditDraft) -> Result<AuditRecord, ApiError>;
    async fn audit_for_workspace(&self, workspace_id: Uuid) -> Result<Vec<AuditRecord>, ApiError>;
    async fn audit_for_agent(
        &self,
        workspace_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AuditRecord>, ApiError>;
    async fn revoke_workspace_sessions(&self, workspace_id: Uuid, at: u64) -> Result<(), ApiError>;
    async fn revoke_workspace_credentials(
        &self,
        workspace_id: Uuid,
        at: u64,
    ) -> Result<(), ApiError>;
    async fn delete_secret_material(&self, workspace_id: Uuid) -> Result<(), ApiError>;
    async fn workspaces_with_status(&self, status: &str) -> Result<Vec<WorkspaceRow>, ApiError>;
    async fn audit_tip(&self, workspace_id: Uuid) -> Result<Option<(u64, [u8; 32])>, ApiError>;
    async fn insert_checkpoint(&self, row: CheckpointRow) -> Result<(), ApiError>;
    async fn latest_checkpoint(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<CheckpointRow>, ApiError>;
    async fn set_secret_status(
        &self,
        workspace_id: Uuid,
        name: &str,
        status: &str,
    ) -> Result<(), ApiError>;
    async fn list_sessions(&self, workspace_id: Uuid) -> Result<Vec<SessionRow>, ApiError>;
}

#[derive(Clone, Debug)]
pub struct CheckpointRow {
    pub workspace_id: Uuid,
    pub seq: u64,
    pub tip_hash: [u8; 32],
    pub kid: String,
    pub signature: Vec<u8>,
    pub anchored_at: Option<u64>,
}

#[derive(Default)]
struct State {
    workspaces: HashMap<Uuid, WorkspaceRow>,
    by_hash: HashMap<[u8; 32], Uuid>,
    keks: HashMap<Uuid, KekRow>,
    secrets: HashMap<Uuid, SecretRow>,
    versions: HashMap<Uuid, VersionRow>,
    agents: HashMap<Uuid, AgentRow>,
    sessions: HashMap<Uuid, SessionRow>,
    audits: Vec<AuditRecord>,
    checkpoints: Vec<CheckpointRow>,
    tips: HashMap<Uuid, [u8; 32]>,
    agent_tips: HashMap<(Uuid, Uuid), ([u8; 32], u64)>,
}

pub struct MemoryStore {
    inner: Mutex<State>,
    fail_appends: AtomicBool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(State::default()),
            fail_appends: AtomicBool::new(false),
        }
    }

    pub fn set_fail_appends(&self, fail: bool) {
        self.fail_appends.store(fail, Ordering::Relaxed);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
#[allow(clippy::unused_async)]
impl Store for MemoryStore {
    async fn insert_workspace(&self, row: WorkspaceRow, kek: KekRow) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        state.by_hash.insert(row.credential_hash, row.id);
        state.workspaces.insert(row.id, row);
        state.keks.insert(kek.id, kek);
        Ok(())
    }

    async fn workspace_by_hash(&self, hash: &[u8; 32]) -> Result<WorkspaceRow, ApiError> {
        let state = lock(&self.inner);
        let id = state.by_hash.get(hash).ok_or(ApiError::Unauthenticated)?;
        state
            .workspaces
            .get(id)
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }

    async fn workspace(&self, id: Uuid) -> Result<WorkspaceRow, ApiError> {
        lock(&self.inner)
            .workspaces
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    async fn set_workspace_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let row = state.workspaces.get_mut(&id).ok_or(ApiError::NotFound)?;
        row.status = status.to_owned();
        Ok(())
    }

    async fn insert_kek(&self, kek: KekRow) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        if kek.status == "active"
            && state
                .keks
                .values()
                .any(|row| row.workspace_id == kek.workspace_id && row.status == "active")
        {
            return Err(ApiError::BadRequest);
        }
        state.keks.insert(kek.id, kek);
        Ok(())
    }

    async fn swap_active_kek(&self, old_id: Uuid, new_kek: KekRow) -> Result<(), ApiError> {
        if new_kek.status != "active" {
            return Err(ApiError::BadRequest);
        }
        let mut state = lock(&self.inner);
        let old = state.keks.get_mut(&old_id).ok_or(ApiError::NotFound)?;
        if old.status != "active" || old.workspace_id != new_kek.workspace_id {
            return Err(ApiError::BadRequest);
        }
        old.status = "decrypt_only".to_owned();
        state.keks.insert(new_kek.id, new_kek);
        Ok(())
    }

    async fn active_kek(&self, workspace_id: Uuid) -> Result<KekRow, ApiError> {
        lock(&self.inner)
            .keks
            .values()
            .find(|kek| kek.workspace_id == workspace_id && kek.status == "active")
            .cloned()
            .ok_or(ApiError::KmsUnavailable)
    }

    async fn kek(&self, id: Uuid) -> Result<KekRow, ApiError> {
        lock(&self.inner)
            .keks
            .get(&id)
            .cloned()
            .ok_or(ApiError::KmsUnavailable)
    }

    async fn list_keks(&self, workspace_id: Uuid) -> Result<Vec<KekRow>, ApiError> {
        Ok(lock(&self.inner)
            .keks
            .values()
            .filter(|kek| kek.workspace_id == workspace_id)
            .cloned()
            .collect())
    }

    async fn set_kek_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let workspace_id = state
            .keks
            .get(&id)
            .map(|kek| kek.workspace_id)
            .ok_or(ApiError::NotFound)?;
        if status == "active"
            && state.keks.values().any(|kek| {
                kek.id != id && kek.status == "active" && kek.workspace_id == workspace_id
            })
        {
            return Err(ApiError::BadRequest);
        }
        state.keks.get_mut(&id).ok_or(ApiError::NotFound)?.status = status.to_owned();
        Ok(())
    }

    async fn next_kek_version(&self, workspace_id: Uuid) -> Result<u32, ApiError> {
        let state = lock(&self.inner);
        let max = state
            .keks
            .values()
            .filter(|kek| kek.workspace_id == workspace_id)
            .map(|kek| kek.version)
            .max()
            .unwrap_or(0);
        Ok(max + 1)
    }

    async fn insert_agent(&self, row: AgentRow) -> Result<(), ApiError> {
        lock(&self.inner).agents.insert(row.id, row);
        Ok(())
    }

    async fn agent(&self, id: Uuid) -> Result<AgentRow, ApiError> {
        lock(&self.inner)
            .agents
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    async fn insert_session(&self, row: SessionRow) -> Result<(), ApiError> {
        lock(&self.inner).sessions.insert(row.id, row);
        Ok(())
    }

    async fn session(&self, id: Uuid) -> Result<SessionRow, ApiError> {
        lock(&self.inner)
            .sessions
            .get(&id)
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }

    async fn revoke_session(&self, id: Uuid, at: u64) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let session = state.sessions.get_mut(&id).ok_or(ApiError::NotFound)?;
        session.revoked_at = Some(at);
        Ok(())
    }

    async fn insert_secret(
        &self,
        secret: SecretRow,
        version: VersionRow,
        audit: AuditDraft,
    ) -> Result<(), ApiError> {
        ensure_gateway(version.wrap_mode, version.e2e_encapsulation.as_deref())?;
        self.write_checked(|state| {
            append_locked(state, audit, self.fail_appends.load(Ordering::Relaxed))?;
            state.secrets.insert(secret.id, secret);
            state.versions.insert(version.id, version);
            Ok(())
        })
    }

    async fn insert_version(&self, version: VersionRow, audit: AuditDraft) -> Result<(), ApiError> {
        ensure_gateway(version.wrap_mode, version.e2e_encapsulation.as_deref())?;
        self.write_checked(|state| {
            if !state.secrets.contains_key(&version.secret_id) {
                return Err(ApiError::NotFound);
            }
            append_locked(state, audit, self.fail_appends.load(Ordering::Relaxed))?;
            state.versions.insert(version.id, version);
            Ok(())
        })
    }

    async fn secret_by_name(&self, workspace_id: Uuid, name: &str) -> Result<SecretRow, ApiError> {
        lock(&self.inner)
            .secrets
            .values()
            .find(|secret| secret.workspace_id == workspace_id && secret.name == name)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    async fn latest_version(&self, secret_id: Uuid) -> Result<VersionRow, ApiError> {
        lock(&self.inner)
            .versions
            .values()
            .filter(|version| version.secret_id == secret_id)
            .max_by_key(|version| version.version)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    async fn versions_for_kek(&self, kek_id: Uuid) -> Result<Vec<VersionRow>, ApiError> {
        Ok(lock(&self.inner)
            .versions
            .values()
            .filter(|version| version.kek_id == kek_id)
            .cloned()
            .collect())
    }

    async fn update_wrap(
        &self,
        version_id: Uuid,
        expected_kek: Uuid,
        sealed: SealedSecret,
        new_kek: Uuid,
    ) -> Result<bool, ApiError> {
        let mut state = lock(&self.inner);
        let version = state
            .versions
            .get_mut(&version_id)
            .ok_or(ApiError::NotFound)?;
        if version.wrap_mode != WrapMode::Gateway {
            return Err(ApiError::BadRequest);
        }
        if version.kek_id != expected_kek {
            return Ok(false);
        }
        version.sealed.dek_wrap_alg = sealed.dek_wrap_alg;
        version.sealed.dek_wrap_nonce = sealed.dek_wrap_nonce;
        version.sealed.dek_wrapped = sealed.dek_wrapped;
        version.kek_id = new_kek;
        Ok(true)
    }

    async fn append_audit(&self, draft: AuditDraft) -> Result<AuditRecord, ApiError> {
        let mut state = lock(&self.inner);
        append_locked(&mut state, draft, self.fail_appends.load(Ordering::Relaxed))
    }

    async fn audit_for_workspace(&self, workspace_id: Uuid) -> Result<Vec<AuditRecord>, ApiError> {
        Ok(lock(&self.inner)
            .audits
            .iter()
            .filter(|event| event.workspace_id == workspace_id)
            .cloned()
            .collect())
    }

    async fn audit_for_agent(
        &self,
        workspace_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AuditRecord>, ApiError> {
        Ok(lock(&self.inner)
            .audits
            .iter()
            .filter(|event| event.workspace_id == workspace_id && event.agent_id == Some(agent_id))
            .cloned()
            .collect())
    }

    async fn revoke_workspace_sessions(&self, workspace_id: Uuid, at: u64) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        for session in state.sessions.values_mut() {
            if session.workspace_id == workspace_id && session.revoked_at.is_none() {
                session.revoked_at = Some(at);
            }
        }
        Ok(())
    }

    async fn revoke_workspace_credentials(
        &self,
        workspace_id: Uuid,
        _at: u64,
    ) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let hashes: Vec<[u8; 32]> = state
            .by_hash
            .iter()
            .filter(|(_, id)| **id == workspace_id)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in hashes {
            state.by_hash.remove(&hash);
        }
        Ok(())
    }

    async fn delete_secret_material(&self, workspace_id: Uuid) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let secret_ids: Vec<Uuid> = state
            .secrets
            .values()
            .filter(|secret| secret.workspace_id == workspace_id)
            .map(|secret| secret.id)
            .collect();
        state
            .versions
            .retain(|_, version| version.workspace_id != workspace_id);
        for id in &secret_ids {
            state.secrets.remove(id);
        }
        state.keks.retain(|_, kek| kek.workspace_id != workspace_id);
        Ok(())
    }

    async fn workspaces_with_status(&self, status: &str) -> Result<Vec<WorkspaceRow>, ApiError> {
        Ok(lock(&self.inner)
            .workspaces
            .values()
            .filter(|row| row.status == status)
            .cloned()
            .collect())
    }

    async fn audit_tip(&self, workspace_id: Uuid) -> Result<Option<(u64, [u8; 32])>, ApiError> {
        let state = lock(&self.inner);
        let Some(workspace) = state.workspaces.get(&workspace_id) else {
            return Ok(None);
        };
        if workspace.audit_seq == 0 {
            return Ok(None);
        }
        let hash = state.tips.get(&workspace_id).copied().unwrap_or([0u8; 32]);
        Ok(Some((workspace.audit_seq, hash)))
    }

    async fn insert_checkpoint(&self, row: CheckpointRow) -> Result<(), ApiError> {
        lock(&self.inner).checkpoints.push(row);
        Ok(())
    }

    async fn latest_checkpoint(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<CheckpointRow>, ApiError> {
        Ok(lock(&self.inner)
            .checkpoints
            .iter()
            .rev()
            .find(|row| row.workspace_id == workspace_id)
            .cloned())
    }

    async fn set_secret_status(
        &self,
        workspace_id: Uuid,
        name: &str,
        status: &str,
    ) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let secret = state
            .secrets
            .values_mut()
            .find(|secret| secret.workspace_id == workspace_id && secret.name == name)
            .ok_or(ApiError::NotFound)?;
        secret.status = status.to_owned();
        Ok(())
    }

    async fn list_sessions(&self, workspace_id: Uuid) -> Result<Vec<SessionRow>, ApiError> {
        Ok(lock(&self.inner)
            .sessions
            .values()
            .filter(|session| session.workspace_id == workspace_id)
            .cloned()
            .collect())
    }
}

impl MemoryStore {
    fn write_checked(
        &self,
        op: impl FnOnce(&mut State) -> Result<(), ApiError>,
    ) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        op(&mut state)
    }
}

fn append_locked(
    state: &mut State,
    draft: AuditDraft,
    fail: bool,
) -> Result<AuditRecord, ApiError> {
    if fail {
        return Err(ApiError::AuditFailed);
    }
    let seq = {
        let workspace = state
            .workspaces
            .get_mut(&draft.workspace_id)
            .ok_or(ApiError::NotFound)?;
        workspace.audit_seq += 1;
        workspace.audit_seq
    };
    let prev = state
        .tips
        .get(&draft.workspace_id)
        .copied()
        .unwrap_or([0u8; 32]);
    let (agent_prev, agent_seq) = if let Some(agent) = draft.agent_id {
        let (hash, seq) = state
            .agent_tips
            .get(&(draft.workspace_id, agent))
            .copied()
            .unwrap_or(([0u8; 32], 0));
        (hash, seq + 1)
    } else {
        ([0u8; 32], 0)
    };
    let record = commit_event(draft, seq, prev, agent_prev, agent_seq);
    if let Some(agent) = record.agent_id {
        if let Some(hash) = record.agent_hash {
            state
                .agent_tips
                .insert((record.workspace_id, agent), (hash, record.agent_seq));
        }
    }
    state.tips.insert(record.workspace_id, record.hash);
    state.audits.push(record.clone());
    Ok(record)
}

fn lock(mutex: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    mutex.lock().expect("store lock poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditDraft;
    use credentials_crypto::SealedSecret;

    #[tokio::test]
    async fn writers_reject_e2e_until_that_mode_exists() {
        let store = MemoryStore::new();
        let err = store
            .insert_version(dummy_version(WrapMode::E2e), dummy_audit())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "bad_request");
    }

    fn dummy_version(mode: WrapMode) -> VersionRow {
        VersionRow {
            id: Uuid::now_v7(),
            secret_id: Uuid::now_v7(),
            workspace_id: Uuid::now_v7(),
            version: 1,
            sealed: SealedSecret {
                payload_alg: "aes-256-gcm-v1".into(),
                payload_nonce: [0; 12],
                payload_ciphertext: vec![1, 2, 3],
                dek_wrap_alg: "aes-256-gcm-v1".into(),
                dek_wrap_nonce: [0; 12],
                dek_wrapped: vec![4, 5, 6],
                plaintext_len: 1,
            },
            kek_id: Uuid::now_v7(),
            wrap_mode: mode,
            e2e_encapsulation: Some(vec![7]),
        }
    }

    fn dummy_audit() -> AuditDraft {
        AuditDraft {
            workspace_id: Uuid::now_v7(),
            agent_id: None,
            event_type: "secret.write".into(),
            occurred_at_nanos: 1,
            fields: Vec::new(),
        }
    }
}
