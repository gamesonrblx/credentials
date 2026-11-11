//! In-memory store for the pre-alpha gateway.
//!
//! A SQLite or Postgres adapter can implement [`Store`] later. Audit append
//! and the row it records share one lock, so a failed append does not leave a
//! half-written access.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use credentials_crypto::SealedSecret;
use uuid::Uuid;

use crate::audit::{agent_hash, canonical_body, workspace_hash, AuditDraft, AuditRecord};
use crate::policy::DeliveryPolicy;
use crate::ApiError;

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

pub trait Store: Send + Sync {
    fn insert_workspace(&self, row: WorkspaceRow, kek: KekRow) -> Result<(), ApiError>;
    fn workspace_by_hash(&self, hash: &[u8; 32]) -> Result<WorkspaceRow, ApiError>;
    fn workspace(&self, id: Uuid) -> Result<WorkspaceRow, ApiError>;
    fn set_workspace_status(&self, id: Uuid, status: &str) -> Result<(), ApiError>;
    fn insert_kek(&self, kek: KekRow) -> Result<(), ApiError>;
    fn active_kek(&self, workspace_id: Uuid) -> Result<KekRow, ApiError>;
    fn kek(&self, id: Uuid) -> Result<KekRow, ApiError>;
    fn set_kek_status(&self, id: Uuid, status: &str) -> Result<(), ApiError>;
    fn next_kek_version(&self, workspace_id: Uuid) -> Result<u32, ApiError>;
    fn insert_agent(&self, row: AgentRow) -> Result<(), ApiError>;
    fn agent(&self, id: Uuid) -> Result<AgentRow, ApiError>;
    fn insert_session(&self, row: SessionRow) -> Result<(), ApiError>;
    fn session(&self, id: Uuid) -> Result<SessionRow, ApiError>;
    fn revoke_session(&self, id: Uuid, at: u64) -> Result<(), ApiError>;
    fn insert_secret(
        &self,
        secret: SecretRow,
        version: VersionRow,
        audit: AuditDraft,
    ) -> Result<(), ApiError>;
    fn insert_version(&self, version: VersionRow, audit: AuditDraft) -> Result<(), ApiError>;
    fn secret_by_name(&self, workspace_id: Uuid, name: &str) -> Result<SecretRow, ApiError>;
    fn latest_version(&self, secret_id: Uuid) -> Result<VersionRow, ApiError>;
    fn versions_for_kek(&self, kek_id: Uuid) -> Result<Vec<VersionRow>, ApiError>;
    fn update_wrap(
        &self,
        version_id: Uuid,
        sealed: SealedSecret,
        kek_id: Uuid,
    ) -> Result<(), ApiError>;
    fn append_audit(&self, draft: AuditDraft) -> Result<AuditRecord, ApiError>;
    fn audit_for_workspace(&self, workspace_id: Uuid) -> Result<Vec<AuditRecord>, ApiError>;
    fn audit_for_agent(
        &self,
        workspace_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AuditRecord>, ApiError>;
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

impl Store for MemoryStore {
    fn insert_workspace(&self, row: WorkspaceRow, kek: KekRow) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        state.by_hash.insert(row.credential_hash, row.id);
        state.workspaces.insert(row.id, row);
        state.keks.insert(kek.id, kek);
        Ok(())
    }

    fn workspace_by_hash(&self, hash: &[u8; 32]) -> Result<WorkspaceRow, ApiError> {
        let state = lock(&self.inner);
        let id = state.by_hash.get(hash).ok_or(ApiError::Unauthenticated)?;
        state
            .workspaces
            .get(id)
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }

    fn workspace(&self, id: Uuid) -> Result<WorkspaceRow, ApiError> {
        lock(&self.inner)
            .workspaces
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    fn set_workspace_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let row = state.workspaces.get_mut(&id).ok_or(ApiError::NotFound)?;
        row.status = status.to_owned();
        Ok(())
    }

    fn insert_kek(&self, kek: KekRow) -> Result<(), ApiError> {
        lock(&self.inner).keks.insert(kek.id, kek);
        Ok(())
    }

    fn active_kek(&self, workspace_id: Uuid) -> Result<KekRow, ApiError> {
        lock(&self.inner)
            .keks
            .values()
            .find(|kek| kek.workspace_id == workspace_id && kek.status == "active")
            .cloned()
            .ok_or(ApiError::KmsUnavailable)
    }

    fn kek(&self, id: Uuid) -> Result<KekRow, ApiError> {
        lock(&self.inner)
            .keks
            .get(&id)
            .cloned()
            .ok_or(ApiError::KmsUnavailable)
    }

    fn set_kek_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let kek = state.keks.get_mut(&id).ok_or(ApiError::NotFound)?;
        kek.status = status.to_owned();
        Ok(())
    }

    fn next_kek_version(&self, workspace_id: Uuid) -> Result<u32, ApiError> {
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

    fn insert_agent(&self, row: AgentRow) -> Result<(), ApiError> {
        lock(&self.inner).agents.insert(row.id, row);
        Ok(())
    }

    fn agent(&self, id: Uuid) -> Result<AgentRow, ApiError> {
        lock(&self.inner)
            .agents
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    fn insert_session(&self, row: SessionRow) -> Result<(), ApiError> {
        lock(&self.inner).sessions.insert(row.id, row);
        Ok(())
    }

    fn session(&self, id: Uuid) -> Result<SessionRow, ApiError> {
        lock(&self.inner)
            .sessions
            .get(&id)
            .cloned()
            .ok_or(ApiError::Unauthenticated)
    }

    fn revoke_session(&self, id: Uuid, at: u64) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let session = state.sessions.get_mut(&id).ok_or(ApiError::NotFound)?;
        session.revoked_at = Some(at);
        Ok(())
    }

    fn insert_secret(
        &self,
        secret: SecretRow,
        version: VersionRow,
        audit: AuditDraft,
    ) -> Result<(), ApiError> {
        self.write_checked(|state| {
            append_locked(state, audit, self.fail_appends.load(Ordering::Relaxed))?;
            state.secrets.insert(secret.id, secret);
            state.versions.insert(version.id, version);
            Ok(())
        })
    }

    fn insert_version(&self, version: VersionRow, audit: AuditDraft) -> Result<(), ApiError> {
        self.write_checked(|state| {
            append_locked(state, audit, self.fail_appends.load(Ordering::Relaxed))?;
            state.versions.insert(version.id, version);
            Ok(())
        })
    }

    fn secret_by_name(&self, workspace_id: Uuid, name: &str) -> Result<SecretRow, ApiError> {
        lock(&self.inner)
            .secrets
            .values()
            .find(|secret| secret.workspace_id == workspace_id && secret.name == name)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    fn latest_version(&self, secret_id: Uuid) -> Result<VersionRow, ApiError> {
        lock(&self.inner)
            .versions
            .values()
            .filter(|version| version.secret_id == secret_id)
            .max_by_key(|version| version.version)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    fn versions_for_kek(&self, kek_id: Uuid) -> Result<Vec<VersionRow>, ApiError> {
        Ok(lock(&self.inner)
            .versions
            .values()
            .filter(|version| version.kek_id == kek_id)
            .cloned()
            .collect())
    }

    fn update_wrap(
        &self,
        version_id: Uuid,
        sealed: SealedSecret,
        kek_id: Uuid,
    ) -> Result<(), ApiError> {
        let mut state = lock(&self.inner);
        let version = state
            .versions
            .get_mut(&version_id)
            .ok_or(ApiError::NotFound)?;
        version.sealed = sealed;
        version.kek_id = kek_id;
        Ok(())
    }

    fn append_audit(&self, draft: AuditDraft) -> Result<AuditRecord, ApiError> {
        let mut state = lock(&self.inner);
        append_locked(&mut state, draft, self.fail_appends.load(Ordering::Relaxed))
    }

    fn audit_for_workspace(&self, workspace_id: Uuid) -> Result<Vec<AuditRecord>, ApiError> {
        Ok(lock(&self.inner)
            .audits
            .iter()
            .filter(|event| event.workspace_id == workspace_id)
            .cloned()
            .collect())
    }

    fn audit_for_agent(
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
    let mut record = AuditRecord {
        workspace_id: draft.workspace_id,
        seq,
        agent_id: draft.agent_id,
        agent_seq,
        event_type: draft.event_type,
        occurred_at_nanos: draft.occurred_at_nanos,
        fields: draft.fields,
        prev_hash: prev,
        hash: [0u8; 32],
        agent_prev_hash: agent_prev,
        agent_hash: None,
    };
    let body = canonical_body(&record);
    record.hash = workspace_hash(&prev, &body);
    if record.agent_id.is_some() {
        let hash = agent_hash(&body);
        record.agent_hash = Some(hash);
        if let Some(agent) = record.agent_id {
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
