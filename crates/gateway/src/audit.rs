//! Hash-chained audit records.
//!
//! `hash = SHA-256(prev_hash || body)` and, when the event has an agent,
//! `agent_hash = SHA-256(body)`. `body` includes `agent_prev_hash`, so the
//! workspace chain commits to the per-agent links. The encoding is the one in
//! the encryption spec.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AuditValue {
    String(String),
    Uuid(Uuid),
    U64(u64),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub struct AuditDraft {
    pub workspace_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub event_type: String,
    pub occurred_at_nanos: u64,
    pub fields: Vec<(String, AuditValue)>,
}

#[derive(Clone, Debug)]
pub struct AuditRecord {
    pub workspace_id: Uuid,
    pub seq: u64,
    pub agent_id: Option<Uuid>,
    pub agent_seq: u64,
    pub event_type: String,
    pub occurred_at_nanos: u64,
    pub fields: Vec<(String, AuditValue)>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
    pub agent_prev_hash: [u8; 32],
    pub agent_hash: Option<[u8; 32]>,
}

/// Hash one event. Callers allocate `seq` and the previous tips. The store
/// persists the returned record and does not recompute it later.
pub fn commit_event(
    draft: AuditDraft,
    seq: u64,
    prev_hash: [u8; 32],
    agent_prev_hash: [u8; 32],
    agent_seq: u64,
) -> AuditRecord {
    let mut record = AuditRecord {
        workspace_id: draft.workspace_id,
        seq,
        agent_id: draft.agent_id,
        agent_seq,
        event_type: draft.event_type,
        occurred_at_nanos: draft.occurred_at_nanos,
        fields: draft.fields,
        prev_hash,
        hash: [0u8; 32],
        agent_prev_hash,
        agent_hash: None,
    };
    let body = canonical_body(&record);
    record.hash = workspace_hash(&prev_hash, &body);
    if record.agent_id.is_some() {
        record.agent_hash = Some(agent_hash(&body));
    }
    record
}

pub fn canonical_body(record: &AuditRecord) -> Vec<u8> {
    let mut fields = record.fields.clone();
    fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut out = Vec::new();
    out.push(0x01);
    out.extend_from_slice(&record.seq.to_be_bytes());
    out.extend_from_slice(record.workspace_id.as_bytes());
    match record.agent_id {
        Some(id) => out.extend_from_slice(id.as_bytes()),
        None => out.extend_from_slice(&[0u8; 16]),
    }
    out.extend_from_slice(&record.agent_seq.to_be_bytes());
    out.extend_from_slice(&record.agent_prev_hash);
    out.extend_from_slice(&record.occurred_at_nanos.to_be_bytes());
    push_str_u16(&mut out, &record.event_type);
    let count = u16::try_from(fields.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&count.to_be_bytes());
    for (key, value) in fields.into_iter().take(count as usize) {
        push_str_u16(&mut out, &key);
        match value {
            AuditValue::String(text) => {
                out.push(0x01);
                let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&text.as_bytes()[..len as usize]);
            }
            AuditValue::Uuid(id) => {
                out.push(0x02);
                out.extend_from_slice(id.as_bytes());
            }
            AuditValue::U64(n) => {
                out.push(0x03);
                out.extend_from_slice(&n.to_be_bytes());
            }
            AuditValue::Bool(flag) => {
                out.push(0x04);
                out.push(u8::from(flag));
            }
        }
    }
    out
}

pub fn workspace_hash(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(body);
    digest32(hasher)
}

pub fn agent_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    digest32(hasher)
}

pub fn verify_chain(events: &[AuditRecord]) -> bool {
    let mut prev = [0u8; 32];
    let mut agent_tips: Vec<(Uuid, [u8; 32], u64)> = Vec::new();
    for (index, event) in events.iter().enumerate() {
        if event.seq != index as u64 + 1 || event.prev_hash != prev {
            return false;
        }
        let expected_agent_prev = if let Some(agent) = event.agent_id {
            agent_tips
                .iter()
                .find(|(id, _, _)| *id == agent)
                .map(|(_, hash, _)| *hash)
                .unwrap_or([0u8; 32])
        } else {
            [0u8; 32]
        };
        if event.agent_prev_hash != expected_agent_prev {
            return false;
        }
        let body = canonical_body(event);
        let hash = workspace_hash(&prev, &body);
        if hash != event.hash {
            return false;
        }
        if let Some(agent) = event.agent_id {
            let ah = agent_hash(&body);
            if event.agent_hash != Some(ah) {
                return false;
            }
            if let Some(slot) = agent_tips.iter_mut().find(|(id, _, _)| *id == agent) {
                slot.1 = ah;
                slot.2 = event.agent_seq;
            } else {
                agent_tips.push((agent, ah, event.agent_seq));
            }
        }
        prev = hash;
    }
    true
}

fn push_str_u16(out: &mut Vec<u8>, text: &str) {
    let len = u16::try_from(text.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&text.as_bytes()[..len as usize]);
}

fn digest32(hasher: Sha256) -> [u8; 32] {
    let out = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(out.as_slice());
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_detects_a_rewritten_event() {
        let workspace = Uuid::now_v7();
        let agent = Uuid::now_v7();
        let first = sample(
            workspace,
            Some(agent),
            1,
            1,
            [0u8; 32],
            [0u8; 32],
            "secret.write",
        );
        let second = sample(
            workspace,
            Some(agent),
            2,
            2,
            first.hash,
            first.agent_hash.unwrap(),
            "secret.access.allowed",
        );
        assert!(verify_chain(&[first.clone(), second.clone()]));
        let mut tampered = second.clone();
        tampered.event_type = "secret.access.denied".to_owned();
        assert!(!verify_chain(&[first, tampered]));
    }

    fn sample(
        workspace: Uuid,
        agent: Option<Uuid>,
        seq: u64,
        agent_seq: u64,
        prev: [u8; 32],
        agent_prev: [u8; 32],
        event_type: &str,
    ) -> AuditRecord {
        let mut record = AuditRecord {
            workspace_id: workspace,
            seq,
            agent_id: agent,
            agent_seq,
            event_type: event_type.to_owned(),
            occurred_at_nanos: 10,
            fields: vec![("reason".to_owned(), AuditValue::String("ok".to_owned()))],
            prev_hash: prev,
            hash: [0u8; 32],
            agent_prev_hash: agent_prev,
            agent_hash: None,
        };
        let body = canonical_body(&record);
        record.hash = workspace_hash(&prev, &body);
        if agent.is_some() {
            record.agent_hash = Some(agent_hash(&body));
        }
        record
    }
}
