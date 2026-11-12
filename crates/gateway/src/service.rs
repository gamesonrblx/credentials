//! Authorize, audit, unwrap, inject.
//!
//! The audit event is committed before the KEK is unwrapped. If that append
//! fails, the data key stays wrapped.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use credentials_crypto::{
    open_secret, random_bytes, rewrap_dek, seal_secret, DevPolicy, KekContext, OpenSecret,
    RootKeyProvider, RootKeyState, UnwrappedKek, VersionIds, DEFAULT_MAX_SECRET_BYTES,
    E2E_DEK_WRAP_ALG, E2E_ENCAPSULATION_KEY_LEN, E2E_ENCAPSULATION_LEN, PAYLOAD_ALG,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing as ZeroizingBuf;

use crate::anchor::{
    checkpoint_message, AuditAnchor, MemoryAnchor, AUDIT_ANCHOR_MAX_LAG, CHECKPOINT_EVERY_EVENTS,
    CHECKPOINT_EVERY_SECS,
};
use crate::audit::{verify_chain, AuditDraft, AuditRecord, AuditValue};
use crate::dpop::{self, DpopKey};
use crate::names::valid_secret_name;
use crate::policy::{
    delivery_allowed, format_header, host_allowed, https_host, scope_allowed_on_agent,
    scope_allows, validate_policy, Delivery, DeliveryPolicy,
};
use crate::store::{
    AgentRow, KekRow, RecipientRow, RewrapJobRow, SecretRow, SessionRow, Store, VersionRow,
    WorkspaceKeyRow, WorkspaceRow, WrapMode,
};
use crate::token::{AgentClaims, DevSigner, DEFAULT_TTL_SECS, MAX_TTL_SECS};
use crate::upstream::{Outbound, Upstream};
use crate::ApiError;

pub const ISSUER: &str = "https://credentials.local/v1";
const KEK_CACHE_TTL: Duration = Duration::from_secs(60);

pub struct Clock;

pub trait Now: Send + Sync {
    fn unix_secs(&self) -> u64;
    fn unix_nanos(&self) -> u64;
}

impl Now for Clock {
    fn unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn unix_nanos(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

pub struct ManualClock {
    secs: AtomicU64,
}

impl ManualClock {
    pub fn new(secs: u64) -> Self {
        Self {
            secs: AtomicU64::new(secs),
        }
    }

    pub fn set(&self, secs: u64) {
        self.secs.store(secs, Ordering::Relaxed);
    }
}

impl Now for ManualClock {
    fn unix_secs(&self) -> u64 {
        self.secs.load(Ordering::Relaxed)
    }

    fn unix_nanos(&self) -> u64 {
        self.unix_secs().saturating_mul(1_000_000_000)
    }
}

struct CachedKek {
    workspace_id: Uuid,
    key: ZeroizingBuf<[u8; 32]>,
    expires: Instant,
}

struct AnchorTrack {
    started_at: u64,
    last_checkpoint_at: HashMap<Uuid, u64>,
    failed_since: Option<u64>,
    max_lag: u64,
}

pub struct Gateway {
    store: Arc<dyn Store>,
    kms: Arc<dyn RootKeyProvider>,
    upstream: Arc<dyn Upstream>,
    anchor: Arc<dyn AuditAnchor>,
    signer: DevSigner,
    issuer: String,
    audience: String,
    clock: Arc<dyn Now>,
    kek_cache: Mutex<HashMap<Uuid, CachedKek>>,
    kek_flight: Mutex<HashMap<Uuid, Arc<Mutex<()>>>>,
    anchor_track: Mutex<AnchorTrack>,
    pub metrics_integrity: AtomicU64,
    unwrap_secrets: bool,
}

pub struct CreatedWorkspace {
    pub id: Uuid,
    pub credential: String,
}

pub struct CreatedVersion {
    pub secret_id: Uuid,
    pub version_id: Uuid,
    pub version: u32,
}

pub struct CreatedSession {
    pub session_id: Uuid,
    pub token: String,
    pub expires_at: u64,
}

pub struct InjectRequest {
    pub token: String,
    pub dpop: String,
    pub secret: String,
    pub delivery: Delivery,
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub htm: String,
    pub htu: String,
    pub local_channel: bool,
}

pub struct InjectResponse {
    pub upstream_status: u16,
    pub body: Vec<u8>,
}

/// Ciphertext columns for a secret the caller sealed. No plaintext field.
pub struct E2eSubmission {
    pub secret_id: Uuid,
    pub version_id: Uuid,
    pub workspace_key_id: Uuid,
    pub payload_nonce: [u8; 12],
    pub payload_ciphertext: Vec<u8>,
    pub dek_wrap_nonce: [u8; 12],
    pub dek_wrapped: Vec<u8>,
    pub encapsulation: Vec<u8>,
    pub plaintext_len: usize,
}

impl std::fmt::Debug for InjectResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InjectResponse")
            .field("upstream_status", &self.upstream_status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Gateway {
    pub fn new(
        store: Arc<dyn Store>,
        kms: Arc<dyn RootKeyProvider>,
        upstream: Arc<dyn Upstream>,
        clock: Arc<dyn Now>,
    ) -> Result<Self, ApiError> {
        Self::with_signer(store, kms, upstream, clock, DevSigner::generate("dev-1")?)
    }

    pub fn with_signer(
        store: Arc<dyn Store>,
        kms: Arc<dyn RootKeyProvider>,
        upstream: Arc<dyn Upstream>,
        clock: Arc<dyn Now>,
        signer: DevSigner,
    ) -> Result<Self, ApiError> {
        Self::with_anchor(
            store,
            kms,
            upstream,
            clock,
            signer,
            Arc::new(MemoryAnchor::new()),
        )
    }

    pub fn with_anchor(
        store: Arc<dyn Store>,
        kms: Arc<dyn RootKeyProvider>,
        upstream: Arc<dyn Upstream>,
        clock: Arc<dyn Now>,
        signer: DevSigner,
        anchor: Arc<dyn AuditAnchor>,
    ) -> Result<Self, ApiError> {
        if !DevPolicy::from_env().allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
        let started_at = clock.unix_secs();
        Ok(Self {
            store,
            kms,
            upstream,
            anchor,
            signer,
            issuer: ISSUER.to_owned(),
            audience: crate::token::AUDIENCE.to_owned(),
            clock,
            kek_cache: Mutex::new(HashMap::new()),
            kek_flight: Mutex::new(HashMap::new()),
            anchor_track: Mutex::new(AnchorTrack {
                started_at,
                last_checkpoint_at: HashMap::new(),
                failed_since: None,
                max_lag: AUDIT_ANCHOR_MAX_LAG,
            }),
            metrics_integrity: AtomicU64::new(0),
            unwrap_secrets: true,
        })
    }

    /// Production control plane. It does not take a provider that can unwrap
    /// secret keys. `policy` must be production. Gateway-wrapped rows fail
    /// closed. End-to-end rows are released as ciphertext.
    pub fn control_plane(
        store: Arc<dyn Store>,
        upstream: Arc<dyn Upstream>,
        clock: Arc<dyn Now>,
        signer: DevSigner,
        anchor: Arc<dyn AuditAnchor>,
        policy: DevPolicy,
    ) -> Result<Self, ApiError> {
        if policy.allow_dev {
            return Err(ApiError::KmsUnavailable);
        }
        let started_at = clock.unix_secs();
        Ok(Self {
            store,
            kms: Arc::new(credentials_crypto::RejectingRootKeys),
            upstream,
            anchor,
            signer,
            issuer: ISSUER.to_owned(),
            audience: crate::token::AUDIENCE.to_owned(),
            clock,
            kek_cache: Mutex::new(HashMap::new()),
            kek_flight: Mutex::new(HashMap::new()),
            anchor_track: Mutex::new(AnchorTrack {
                started_at,
                last_checkpoint_at: HashMap::new(),
                failed_since: None,
                max_lag: AUDIT_ANCHOR_MAX_LAG,
            }),
            metrics_integrity: AtomicU64::new(0),
            unwrap_secrets: false,
        })
    }

    pub fn set_issuer(&mut self, issuer: impl Into<String>) {
        self.issuer = issuer.into();
    }

    pub fn set_audience(&mut self, audience: impl Into<String>) {
        self.audience = audience.into();
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn set_anchor_max_lag(&self, secs: u64) {
        self.anchor_track.lock().expect("anchor lock").max_lag = secs;
    }

    pub async fn create_workspace(&self) -> Result<CreatedWorkspace, ApiError> {
        let id = Uuid::now_v7();
        let kek_id = Uuid::now_v7();
        let (key_ref, wrapped) = if self.unwrap_secrets {
            let key_ref = self.kms.create_tenant_root(id).map_err(map_crypto)?;
            let kek = ZeroizingBuf::new(random_32()?);
            let context = KekContext {
                workspace_id: id,
                kek_id,
                kek_version: 1,
            };
            let wrapped = self
                .kms
                .encrypt(&key_ref, kek.as_slice(), &context)
                .map_err(map_crypto)?;
            (key_ref, wrapped)
        } else {
            ("control-plane".to_owned(), Vec::new())
        };
        let credential = ZeroizingBuf::new(random_32()?);
        let hash = sha256(credential.as_slice());
        self.store
            .insert_workspace(
                WorkspaceRow {
                    id,
                    status: "active".to_owned(),
                    kms_key_ref: key_ref.clone(),
                    credential_hash: hash,
                    audit_seq: 0,
                },
                KekRow {
                    id: kek_id,
                    workspace_id: id,
                    version: 1,
                    status: "active".to_owned(),
                    wrapped_kek: wrapped,
                    kms_key_ref: key_ref,
                },
            )
            .await?;
        let encoded = crate::b64::b64url_encode(credential.as_slice());
        Ok(CreatedWorkspace {
            id,
            credential: encoded,
        })
    }

    pub async fn create_secret(
        &self,
        credential: &str,
        name: &str,
        value: &[u8],
        policy: DeliveryPolicy,
    ) -> Result<CreatedVersion, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if !valid_secret_name(name) {
            return Err(ApiError::BadRequest);
        }
        validate_policy(&policy).map_err(|_| ApiError::InvalidPolicy)?;
        if value.len() > DEFAULT_MAX_SECRET_BYTES {
            return Err(ApiError::PayloadTooLarge);
        }
        let kek_row = self.store.active_kek(workspace.id).await?;
        let kek = self.unwrap_kek(&workspace, &kek_row)?;
        let secret_id = Uuid::now_v7();
        let version_id = Uuid::now_v7();
        let ids = VersionIds {
            workspace_id: workspace.id,
            secret_id,
            version_id,
        };
        let sealed = seal_secret(
            &kek,
            kek_row.id,
            kek_row.version,
            ids,
            value,
            DEFAULT_MAX_SECRET_BYTES,
        )
        .map_err(map_crypto)?;
        self.store
            .insert_secret(
                SecretRow {
                    id: secret_id,
                    workspace_id: workspace.id,
                    name: name.to_owned(),
                    status: "active".to_owned(),
                    policy,
                },
                VersionRow {
                    id: version_id,
                    secret_id,
                    workspace_id: workspace.id,
                    version: 1,
                    sealed,
                    kek_id: kek_row.id,
                    wrap_mode: WrapMode::Gateway,
                    e2e_encapsulation: None,
                },
                self.audit(
                    workspace.id,
                    None,
                    "secret.write",
                    vec![
                        ("secret_id".into(), AuditValue::Uuid(secret_id)),
                        ("version_id".into(), AuditValue::Uuid(version_id)),
                        ("secret_name".into(), AuditValue::String(name.to_owned())),
                    ],
                ),
            )
            .await?;
        Ok(CreatedVersion {
            secret_id,
            version_id,
            version: 1,
        })
    }

    /// A new integer version. The previous ciphertext stays in the store.
    pub async fn create_version(
        &self,
        credential: &str,
        name: &str,
        value: &[u8],
    ) -> Result<CreatedVersion, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if !valid_secret_name(name) {
            return Err(ApiError::BadRequest);
        }
        if value.is_empty() || value.len() > DEFAULT_MAX_SECRET_BYTES {
            return Err(ApiError::PayloadTooLarge);
        }
        let secret = self.store.secret_by_name(workspace.id, name).await?;
        let latest = self.store.latest_version(secret.id).await?;
        let version_n = latest.version.checked_add(1).ok_or(ApiError::BadRequest)?;
        let kek_row = self.store.active_kek(workspace.id).await?;
        let kek = self.unwrap_kek(&workspace, &kek_row)?;
        let version_id = Uuid::now_v7();
        let sealed = seal_secret(
            &kek,
            kek_row.id,
            kek_row.version,
            VersionIds {
                workspace_id: workspace.id,
                secret_id: secret.id,
                version_id,
            },
            value,
            DEFAULT_MAX_SECRET_BYTES,
        )
        .map_err(map_crypto)?;
        self.store
            .insert_version(
                VersionRow {
                    id: version_id,
                    secret_id: secret.id,
                    workspace_id: workspace.id,
                    version: version_n,
                    sealed,
                    kek_id: kek_row.id,
                    wrap_mode: WrapMode::Gateway,
                    e2e_encapsulation: None,
                },
                self.audit(
                    workspace.id,
                    None,
                    "secret.write",
                    vec![
                        ("secret_id".into(), AuditValue::Uuid(secret.id)),
                        ("version_id".into(), AuditValue::Uuid(version_id)),
                        ("secret_name".into(), AuditValue::String(name.to_owned())),
                    ],
                ),
            )
            .await?;
        Ok(CreatedVersion {
            secret_id: secret.id,
            version_id,
            version: version_n,
        })
    }

    /// Store a secret the caller already sealed. This process does not see plaintext.
    pub async fn store_e2e_secret(
        &self,
        credential: &str,
        name: &str,
        policy: DeliveryPolicy,
        submitted: E2eSubmission,
    ) -> Result<CreatedVersion, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if !valid_secret_name(name) {
            return Err(ApiError::BadRequest);
        }
        validate_policy(&policy).map_err(|_| ApiError::InvalidPolicy)?;
        if submitted.plaintext_len == 0 || submitted.plaintext_len > DEFAULT_MAX_SECRET_BYTES {
            return Err(ApiError::PayloadTooLarge);
        }
        if submitted.payload_ciphertext.is_empty()
            || submitted.dek_wrapped.is_empty()
            || submitted.encapsulation.len() != E2E_ENCAPSULATION_LEN
        {
            return Err(ApiError::BadRequest);
        }
        let registered = self.store.workspace_key(workspace.id).await?;
        if registered.id != submitted.workspace_key_id {
            return Err(ApiError::BadRequest);
        }
        let kek_row = self.store.active_kek(workspace.id).await?;
        let version = VersionRow {
            id: submitted.version_id,
            secret_id: submitted.secret_id,
            workspace_id: workspace.id,
            version: 1,
            sealed: credentials_crypto::SealedSecret {
                payload_alg: PAYLOAD_ALG.to_owned(),
                payload_nonce: submitted.payload_nonce,
                payload_ciphertext: submitted.payload_ciphertext,
                dek_wrap_alg: E2E_DEK_WRAP_ALG.to_owned(),
                dek_wrap_nonce: submitted.dek_wrap_nonce,
                dek_wrapped: submitted.dek_wrapped,
                plaintext_len: submitted.plaintext_len,
            },
            kek_id: kek_row.id,
            wrap_mode: WrapMode::E2e,
            e2e_encapsulation: Some(submitted.encapsulation),
        };
        let audit = self.audit(
            workspace.id,
            None,
            "secret.write",
            vec![
                ("secret_id".into(), AuditValue::Uuid(submitted.secret_id)),
                ("version_id".into(), AuditValue::Uuid(submitted.version_id)),
                ("secret_name".into(), AuditValue::String(name.to_owned())),
                ("wrap_mode".into(), AuditValue::String("e2e".into())),
            ],
        );
        if self.store.secret_by_name(workspace.id, name).await.is_err() {
            self.store
                .insert_secret(
                    SecretRow {
                        id: submitted.secret_id,
                        workspace_id: workspace.id,
                        name: name.to_owned(),
                        status: "active".to_owned(),
                        policy,
                    },
                    version,
                    audit,
                )
                .await?;
            return Ok(CreatedVersion {
                secret_id: submitted.secret_id,
                version_id: submitted.version_id,
                version: 1,
            });
        }
        let secret = self.store.secret_by_name(workspace.id, name).await?;
        if secret.id != submitted.secret_id {
            return Err(ApiError::BadRequest);
        }
        let latest = self.store.latest_version(secret.id).await?;
        let version_n = latest.version.checked_add(1).ok_or(ApiError::BadRequest)?;
        let mut version = version;
        version.secret_id = secret.id;
        version.version = version_n;
        self.store.insert_version(version, audit).await?;
        Ok(CreatedVersion {
            secret_id: secret.id,
            version_id: submitted.version_id,
            version: version_n,
        })
    }

    pub async fn workspace_id_for(&self, credential: &str) -> Result<Uuid, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        Ok(workspace.id)
    }

    pub async fn registered_key(&self, credential: &str) -> Result<WorkspaceKeyRow, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.store.workspace_key(workspace.id).await
    }

    pub async fn register_workspace_key(
        &self,
        credential: &str,
        encapsulation_key: &[u8],
    ) -> Result<Uuid, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if encapsulation_key.len() != E2E_ENCAPSULATION_KEY_LEN {
            return Err(ApiError::BadRequest);
        }
        let id = Uuid::now_v7();
        self.store
            .insert_workspace_key(WorkspaceKeyRow {
                id,
                workspace_id: workspace.id,
                encapsulation_key: encapsulation_key.to_vec(),
            })
            .await?;
        Ok(id)
    }

    pub async fn add_recipient(&self, credential: &str, row: RecipientRow) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if row.workspace_id != workspace.id {
            return Err(ApiError::Forbidden);
        }
        self.store.insert_recipient(row).await
    }

    pub async fn list_recipients(&self, credential: &str) -> Result<Vec<RecipientRow>, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.store.list_recipients(workspace.id).await
    }

    pub async fn revoke_recipient(&self, credential: &str, id: Uuid) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        self.store
            .revoke_recipient(workspace.id, id, self.clock.unix_nanos())
            .await
    }

    pub async fn disable_secret(&self, credential: &str, name: &str) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        self.store
            .set_secret_status(workspace.id, name, "disabled")
            .await
    }

    pub async fn list_sessions(&self, credential: &str) -> Result<Vec<SessionRow>, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.store.list_sessions(workspace.id).await
    }

    pub async fn latest_checkpoint(
        &self,
        credential: &str,
    ) -> Result<Option<crate::store::CheckpointRow>, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.store.latest_checkpoint(workspace.id).await
    }

    pub async fn create_agent(
        &self,
        credential: &str,
        display_name: &str,
    ) -> Result<Uuid, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        if display_name.is_empty() || display_name.len() > 128 {
            return Err(ApiError::BadRequest);
        }
        let id = Uuid::now_v7();
        self.store
            .insert_agent(AgentRow {
                id,
                workspace_id: workspace.id,
                display_name: display_name.to_owned(),
                status: "active".to_owned(),
            })
            .await?;
        Ok(id)
    }

    pub async fn create_session(
        &self,
        credential: &str,
        agent_id: Uuid,
        scopes: Vec<String>,
        ttl_seconds: Option<u64>,
        dpop_public_b64: &str,
    ) -> Result<CreatedSession, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        let agent = self.store.agent(agent_id).await?;
        if agent.workspace_id != workspace.id || agent.status != "active" {
            return Err(ApiError::NotFound);
        }
        if scopes.is_empty() || scopes.iter().any(|scope| !scope_allowed_on_agent(scope)) {
            return Err(ApiError::Forbidden);
        }
        let ttl = ttl_seconds.unwrap_or(DEFAULT_TTL_SECS);
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return Err(ApiError::BadRequest);
        }
        let jkt = dpop::thumbprint(dpop_public_b64);
        let now = self.clock.unix_secs();
        let session_id = Uuid::now_v7();
        let token_jti = Uuid::now_v7();
        let exp = now + ttl;
        self.store
            .insert_session(SessionRow {
                id: session_id,
                workspace_id: workspace.id,
                agent_id,
                dpop_jkt: jkt.clone(),
                scopes: scopes.clone(),
                expires_at: exp,
                revoked_at: None,
                token_jti: Some(token_jti),
            })
            .await?;
        let claims = AgentClaims {
            exp,
            iat: now,
            jti: token_jti,
            workspace_id: workspace.id,
            agent_id,
            session_id,
            scopes,
            jkt,
        };
        let token = self.signer.sign(&self.issuer, &self.audience, &claims)?;
        self.store
            .append_audit(self.audit(
                workspace.id,
                Some(agent_id),
                "token.issued",
                vec![
                    ("session_id".into(), AuditValue::Uuid(session_id)),
                    ("jti".into(), AuditValue::Uuid(claims.jti)),
                ],
            ))
            .await?;
        Ok(CreatedSession {
            session_id,
            token,
            expires_at: exp,
        })
    }

    pub async fn revoke_session(&self, credential: &str, session_id: Uuid) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        let session = self.store.session(session_id).await?;
        if session.workspace_id != workspace.id {
            return Err(ApiError::NotFound);
        }
        let now = self.clock.unix_secs();
        self.store.revoke_session(session_id, now).await?;
        if let Some(jti) = session.token_jti {
            self.store
                .revoke_jti(jti, workspace.id, session.expires_at)
                .await?;
        }
        self.store
            .append_audit(self.audit(
                workspace.id,
                Some(session.agent_id),
                "token.revoked",
                vec![("session_id".into(), AuditValue::Uuid(session_id))],
            ))
            .await?;
        Ok(())
    }

    pub async fn inject(&self, request: InjectRequest) -> Result<InjectResponse, ApiError> {
        let now = self.clock.unix_secs();
        let claims = self
            .signer
            .verify(&request.token, &self.issuer, &self.audience, now)?;
        let workspace = self.store.workspace(claims.workspace_id).await?;
        if workspace.status != "active" {
            self.audit_or_fail(
                workspace.id,
                Some(claims.agent_id),
                "secret.access.denied",
                vec![(
                    "reason".into(),
                    AuditValue::String("workspace_inactive".into()),
                )],
            )
            .await?;
            return Err(ApiError::WorkspaceDeleting);
        }
        if self.store.jti_is_revoked(claims.jti, now).await? {
            return Err(ApiError::Unauthenticated);
        }
        let session = self.store.session(claims.session_id).await?;
        if session.revoked_at.is_some()
            || session.workspace_id != claims.workspace_id
            || session.agent_id != claims.agent_id
            || session.dpop_jkt != claims.jkt
            || session.expires_at + 30 < self.clock.unix_secs()
        {
            self.audit_or_fail(
                workspace.id,
                Some(claims.agent_id),
                "secret.access.denied",
                vec![("reason".into(), AuditValue::String("revoked".into()))],
            )
            .await?;
            return Err(ApiError::Unauthenticated);
        }
        let agent = self.store.agent(claims.agent_id).await?;
        if agent.status != "active" {
            return Err(ApiError::Unauthenticated);
        }
        let proof = dpop::verify_dpop(
            &request.dpop,
            &request.token,
            &request.htm,
            &request.htu,
            self.clock.unix_secs(),
        )?;
        if proof.jkt != claims.jkt {
            return Err(ApiError::Unauthenticated);
        }
        self.store
            .claim_dpop_jti(&proof.jti, workspace.id, now + 900)
            .await?;

        let secret = match self
            .store
            .secret_by_name(workspace.id, &request.secret)
            .await
        {
            Ok(secret) => secret,
            Err(ApiError::NotFound) => {
                self.audit_or_fail(
                    workspace.id,
                    Some(claims.agent_id),
                    "secret.access.denied",
                    vec![
                        ("reason".into(), AuditValue::String("not_found".into())),
                        (
                            "secret_name".into(),
                            AuditValue::String(request.secret.clone()),
                        ),
                    ],
                )
                .await?;
                return Err(ApiError::NotFound);
            }
            Err(err) => return Err(err),
        };
        if secret.status != "active"
            || !scope_allows(&claims.scopes, "inject", &secret.name)
            || !delivery_allowed(&secret.policy, request.delivery)
        {
            self.audit_or_fail(
                workspace.id,
                Some(claims.agent_id),
                "secret.access.denied",
                vec![("reason".into(), AuditValue::String("scope".into()))],
            )
            .await?;
            return Err(ApiError::Forbidden);
        }
        if matches!(request.delivery, Delivery::Env | Delivery::Header) && !request.local_channel {
            self.audit_or_fail(
                workspace.id,
                Some(claims.agent_id),
                "secret.access.denied",
                vec![("reason".into(), AuditValue::String("local_channel".into()))],
            )
            .await?;
            return Err(ApiError::Forbidden);
        }
        let host = if matches!(request.delivery, Delivery::Proxy) {
            let host = https_host(&request.url).ok_or(ApiError::Forbidden)?;
            if !host_allowed(&secret.policy.hosts, &host) {
                self.audit_or_fail(
                    workspace.id,
                    Some(claims.agent_id),
                    "secret.access.denied",
                    vec![("reason".into(), AuditValue::String("host".into()))],
                )
                .await?;
                return Err(ApiError::Forbidden);
            }
            Some(host)
        } else {
            None
        };

        self.audit_or_fail(
            workspace.id,
            Some(claims.agent_id),
            "secret.access.allowed",
            access_fields(&secret, None, request.delivery, host.as_deref()),
        )
        .await?;
        self.ensure_anchor_fresh(workspace.id).await?;

        let version = self.store.latest_version(secret.id).await?;
        if version.wrap_mode == WrapMode::E2e {
            return self
                .release_ciphertext(workspace.id, Some(claims.agent_id), &version)
                .await;
        }
        if version.wrap_mode != WrapMode::Gateway || version.e2e_encapsulation.is_some() {
            return Err(ApiError::DecryptFailed);
        }
        let kek_row = self.store.kek(version.kek_id).await?;
        let kek = match self.unwrap_kek(&workspace, &kek_row) {
            Ok(kek) => kek,
            Err(err) => {
                let _ = self
                    .store
                    .append_audit(self.audit(
                        workspace.id,
                        Some(claims.agent_id),
                        "secret.access.failed",
                        vec![("reason".into(), AuditValue::String("kms".into()))],
                    ))
                    .await;
                return Err(err);
            }
        };
        let plaintext = match open_secret(OpenSecret {
            kek: &kek,
            kek_id: kek_row.id,
            kek_version: kek_row.version,
            ids: VersionIds {
                workspace_id: workspace.id,
                secret_id: secret.id,
                version_id: version.id,
            },
            payload_alg: &version.sealed.payload_alg,
            dek_wrap_alg: &version.sealed.dek_wrap_alg,
            payload_nonce: &version.sealed.payload_nonce,
            payload_ciphertext: &version.sealed.payload_ciphertext,
            dek_wrap_nonce: &version.sealed.dek_wrap_nonce,
            dek_wrapped: &version.sealed.dek_wrapped,
        }) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.metrics_integrity.fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .store
                    .append_audit(self.audit(
                        workspace.id,
                        Some(claims.agent_id),
                        "secret.access.failed",
                        vec![("reason".into(), AuditValue::String("integrity".into()))],
                    ))
                    .await;
                return Err(ApiError::DecryptFailed);
            }
        };

        let response = match request.delivery {
            Delivery::Proxy => {
                let header_name = secret
                    .policy
                    .header_name
                    .clone()
                    .ok_or(ApiError::Forbidden)?;
                let header_value = format_header(
                    secret.policy.header_format.as_deref().unwrap_or(""),
                    plaintext.as_slice(),
                )
                .ok_or(ApiError::Forbidden)?;
                self.upstream
                    .forward(Outbound {
                        method: request.method,
                        url: request.url,
                        body: request.body,
                        header_name,
                        header_value,
                    })
                    .await
            }
            Delivery::Header => {
                let header_name = secret
                    .policy
                    .header_name
                    .clone()
                    .ok_or(ApiError::Forbidden)?;
                let value = format_header(
                    secret.policy.header_format.as_deref().unwrap_or(""),
                    plaintext.as_slice(),
                )
                .ok_or(ApiError::Forbidden)?;
                let body = serde_json::json!({ "header_name": header_name, "value": value });
                Ok(crate::upstream::Inbound {
                    status: 200,
                    body: serde_json::to_vec(&body).unwrap_or_default(),
                })
            }
            Delivery::Env => {
                let env_name = secret
                    .policy
                    .env_name
                    .clone()
                    .filter(|name| !name.is_empty())
                    .ok_or(ApiError::Forbidden)?;
                let value = std::str::from_utf8(plaintext.as_slice())
                    .map_err(|_| ApiError::DecryptFailed)?;
                let body = serde_json::json!({ "env_name": env_name, "value": value });
                Ok(crate::upstream::Inbound {
                    status: 200,
                    body: serde_json::to_vec(&body).unwrap_or_default(),
                })
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                let _ = self
                    .store
                    .append_audit(self.audit(
                        workspace.id,
                        Some(claims.agent_id),
                        "secret.access.failed",
                        vec![("reason".into(), AuditValue::String("upstream".into()))],
                    ))
                    .await;
                return Err(err);
            }
        };
        let _ = self
            .store
            .append_audit(self.audit(
                workspace.id,
                Some(claims.agent_id),
                "secret.access.delivered",
                access_fields(&secret, Some(version.id), request.delivery, host.as_deref()),
            ))
            .await;
        Ok(InjectResponse {
            upstream_status: response.status,
            body: response.body,
        })
    }

    async fn release_ciphertext(
        &self,
        workspace_id: Uuid,
        agent_id: Option<Uuid>,
        version: &VersionRow,
    ) -> Result<InjectResponse, ApiError> {
        let key = self.store.workspace_key(workspace_id).await?;
        let encapsulation = version
            .e2e_encapsulation
            .as_deref()
            .ok_or(ApiError::DecryptFailed)?;
        self.audit_or_fail(
            workspace_id,
            agent_id,
            "secret.ciphertext.released",
            vec![
                ("version_id".into(), AuditValue::Uuid(version.id)),
                ("wrap_mode".into(), AuditValue::String("e2e".into())),
            ],
        )
        .await?;
        let body = serde_json::json!({
            "wrap_mode": "e2e",
            "workspace_id": workspace_id,
            "secret_id": version.secret_id,
            "version_id": version.id,
            "workspace_key_id": key.id,
            "payload_nonce": crate::b64::b64std_encode(&version.sealed.payload_nonce),
            "payload_ciphertext": crate::b64::b64std_encode(&version.sealed.payload_ciphertext),
            "dek_wrap_nonce": crate::b64::b64std_encode(&version.sealed.dek_wrap_nonce),
            "dek_wrapped": crate::b64::b64std_encode(&version.sealed.dek_wrapped),
            "e2e_encapsulation": crate::b64::b64std_encode(encapsulation),
            "plaintext_len": version.sealed.plaintext_len,
        });
        Ok(InjectResponse {
            upstream_status: 200,
            body: serde_json::to_vec(&body).unwrap_or_default(),
        })
    }

    pub async fn rotate_kek(&self, credential: &str) -> Result<u32, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        let old = self.store.active_kek(workspace.id).await?;
        let new_version = self.store.next_kek_version(workspace.id).await?;
        let new_id = Uuid::now_v7();
        let raw = ZeroizingBuf::new(random_32()?);
        let context = KekContext {
            workspace_id: workspace.id,
            kek_id: new_id,
            kek_version: new_version,
        };
        let wrapped = self
            .kms
            .encrypt(&workspace.kms_key_ref, raw.as_slice(), &context)
            .map_err(map_crypto)?;
        let job_id = Uuid::now_v7();
        self.store
            .insert_rewrap_job(RewrapJobRow {
                id: job_id,
                workspace_id: workspace.id,
                from_kek_id: old.id,
                to_kek_id: new_id,
                status: "pending".into(),
                wrapped_count: 0,
            })
            .await?;
        self.store
            .swap_active_kek(
                old.id,
                KekRow {
                    id: new_id,
                    workspace_id: workspace.id,
                    version: new_version,
                    status: "active".to_owned(),
                    wrapped_kek: wrapped,
                    kms_key_ref: workspace.kms_key_ref.clone(),
                },
            )
            .await?;
        let wrapped_rows = self
            .rewrap_outstanding_keks(&workspace, old.id, new_id, new_version)
            .await?;
        if wrapped_rows > 0 && !self.store.versions_for_kek(old.id).await?.is_empty() {
            self.store
                .finish_rewrap_job(job_id, "failed", wrapped_rows)
                .await?;
            return Err(ApiError::DecryptFailed);
        }
        if self.store.versions_for_kek(old.id).await?.is_empty() {
            self.store.set_kek_status(old.id, "retired").await?;
        }
        self.store
            .finish_rewrap_job(job_id, "done", wrapped_rows)
            .await?;
        self.store
            .append_audit(self.audit(
                workspace.id,
                None,
                "kek.rotated",
                vec![(
                    "kek_version".into(),
                    AuditValue::U64(u64::from(new_version)),
                )],
            ))
            .await?;
        Ok(new_version)
    }

    pub async fn delete_workspace(&self, credential: &str, confirm: Uuid) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        if confirm != workspace.id {
            return Err(ApiError::BadRequest);
        }
        if workspace.status != "active" {
            return Err(ApiError::WorkspaceDeleting);
        }
        let now = self.clock.unix_secs();
        self.store
            .set_workspace_status(workspace.id, "deleting")
            .await?;
        self.store
            .revoke_workspace_sessions(workspace.id, now)
            .await?;
        self.drop_workspace_keks(workspace.id);
        self.kms
            .schedule_destruction(&workspace.kms_key_ref, now + 7 * 24 * 3600)
            .map_err(map_crypto)?;
        self.store
            .append_audit(self.audit(workspace.id, None, "tenant.delete.scheduled", Vec::new()))
            .await?;
        self.store.delete_secret_material(workspace.id).await?;
        Ok(())
    }

    /// Allowed only while the root key is still pending destruction.
    /// Rows removed at schedule time stay removed. A fresh KEK is minted
    /// when none is active, so the workspace can store new secrets.
    pub async fn cancel_deletion(&self, credential: &str, id: Uuid) -> Result<(), ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        if workspace.id != id {
            return Err(ApiError::NotFound);
        }
        if workspace.status != "deleting" {
            return Err(ApiError::BadRequest);
        }
        let state = self
            .kms
            .root_key_state(&workspace.kms_key_ref)
            .map_err(map_crypto)?;
        let RootKeyState::Pending { not_before_unix } = state else {
            return Err(ApiError::BadRequest);
        };
        if self.clock.unix_secs() >= not_before_unix {
            return Err(ApiError::BadRequest);
        }
        self.kms
            .cancel_destruction(&workspace.kms_key_ref)
            .map_err(map_crypto)?;
        self.store
            .set_workspace_status(workspace.id, "active")
            .await?;
        if self.store.active_kek(workspace.id).await.is_err() {
            self.mint_kek(&workspace).await?;
        }
        self.store
            .append_audit(self.audit(workspace.id, None, "tenant.delete.cancelled", Vec::new()))
            .await?;
        Ok(())
    }

    /// Sets `shredded` once the root key waiting period has elapsed.
    pub async fn poll_shreds(&self) -> Result<u32, ApiError> {
        let now = self.clock.unix_secs();
        let mut count = 0u32;
        for workspace in self.store.workspaces_with_status("deleting").await? {
            let due = self
                .kms
                .destroy_if_due(&workspace.kms_key_ref, now)
                .map_err(map_crypto)?;
            if !due {
                continue;
            }
            self.store
                .revoke_workspace_credentials(workspace.id, now)
                .await?;
            self.store
                .set_workspace_status(workspace.id, "shredded")
                .await?;
            self.drop_workspace_keks(workspace.id);
            self.store
                .append_audit(self.audit(workspace.id, None, "tenant.shredded", Vec::new()))
                .await?;
            count += 1;
        }
        Ok(count)
    }

    async fn mint_kek(&self, workspace: &WorkspaceRow) -> Result<(), ApiError> {
        let version = self.store.next_kek_version(workspace.id).await?;
        let kek_id = Uuid::now_v7();
        let raw = ZeroizingBuf::new(random_32()?);
        let context = KekContext {
            workspace_id: workspace.id,
            kek_id,
            kek_version: version,
        };
        let wrapped = self
            .kms
            .encrypt(&workspace.kms_key_ref, raw.as_slice(), &context)
            .map_err(map_crypto)?;
        self.store
            .insert_kek(KekRow {
                id: kek_id,
                workspace_id: workspace.id,
                version,
                status: "active".to_owned(),
                wrapped_kek: wrapped,
                kms_key_ref: workspace.kms_key_ref.clone(),
            })
            .await
    }

    fn drop_workspace_keks(&self, workspace_id: Uuid) {
        self.kek_cache
            .lock()
            .expect("cache lock")
            .retain(|_, entry| entry.workspace_id != workspace_id);
    }

    pub async fn audit_log(
        &self,
        credential: &str,
        agent_id: Option<Uuid>,
    ) -> Result<Vec<AuditRecord>, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        let events = match agent_id {
            Some(agent) => self.store.audit_for_agent(workspace.id, agent).await?,
            None => self.store.audit_for_workspace(workspace.id).await?,
        };
        if !verify_chain(&self.store.audit_for_workspace(workspace.id).await?) {
            return Err(ApiError::DecryptFailed);
        }
        Ok(events)
    }

    /// Retry a KEK rewrap. A second call wraps nothing and leaves payload bytes alone.
    pub async fn rewrap_outstanding(&self, credential: &str) -> Result<u64, ApiError> {
        let workspace = self.authenticate_workspace(credential).await?;
        self.ensure_active(&workspace)?;
        let active = self.store.active_kek(workspace.id).await?;
        let mut total = 0u64;
        for kek in self.store.list_keks(workspace.id).await? {
            if kek.id == active.id || kek.status == "destroyed" {
                continue;
            }
            total += self.rewrap_between(&workspace, kek.id, active.id).await?;
            if self.store.versions_for_kek(kek.id).await?.is_empty() && kek.status != "retired" {
                self.store.set_kek_status(kek.id, "retired").await?;
            }
        }
        Ok(total)
    }

    async fn rewrap_outstanding_keks(
        &self,
        workspace: &WorkspaceRow,
        from_id: Uuid,
        to_id: Uuid,
        to_version: u32,
    ) -> Result<u64, ApiError> {
        let to = self.store.kek(to_id).await?;
        if to.version != to_version {
            return Err(ApiError::DecryptFailed);
        }
        self.rewrap_between(workspace, from_id, to_id).await
    }

    async fn rewrap_between(
        &self,
        workspace: &WorkspaceRow,
        from_id: Uuid,
        to_id: Uuid,
    ) -> Result<u64, ApiError> {
        let from = self.store.kek(from_id).await?;
        let to = self.store.kek(to_id).await?;
        let old_key = self.unwrap_kek(workspace, &from)?;
        let new_key = self.unwrap_kek(workspace, &to)?;
        let mut count = 0u64;
        for version in self.store.versions_for_kek(from_id).await? {
            if version.wrap_mode != WrapMode::Gateway || version.e2e_encapsulation.is_some() {
                return Err(ApiError::DecryptFailed);
            }
            let payload = version.sealed.payload_ciphertext.clone();
            let nonce = version.sealed.payload_nonce;
            let sealed = rewrap_dek(
                UnwrappedKek {
                    key: &old_key,
                    id: from.id,
                    version: from.version,
                },
                UnwrappedKek {
                    key: &new_key,
                    id: to.id,
                    version: to.version,
                },
                VersionIds {
                    workspace_id: version.workspace_id,
                    secret_id: version.secret_id,
                    version_id: version.id,
                },
                &version.sealed,
            )
            .map_err(|_| ApiError::DecryptFailed)?;
            if sealed.payload_ciphertext != payload || sealed.payload_nonce != nonce {
                return Err(ApiError::DecryptFailed);
            }
            if self
                .store
                .update_wrap(version.id, from_id, sealed, to_id)
                .await?
            {
                count += 1;
            }
            let updated = self.store.latest_version(version.secret_id).await?;
            if updated.id == version.id && updated.sealed.payload_ciphertext != payload {
                return Err(ApiError::DecryptFailed);
            }
        }
        Ok(count)
    }

    async fn authenticate_workspace(&self, credential: &str) -> Result<WorkspaceRow, ApiError> {
        let raw = crate::b64::b64url_decode(credential)?;
        if raw.len() != 32 {
            return Err(ApiError::Unauthenticated);
        }
        let hash = sha256(&raw);
        self.store.workspace_by_hash(&hash).await
    }

    fn ensure_active(&self, workspace: &WorkspaceRow) -> Result<(), ApiError> {
        if workspace.status == "active" {
            Ok(())
        } else {
            Err(ApiError::WorkspaceDeleting)
        }
    }

    /// Sign the current audit tip when 1,000 events or 60 seconds have passed.
    pub async fn publish_checkpoints(&self) -> Result<u32, ApiError> {
        self.publish_all(false).await
    }

    /// Sign every workspace tip, including ones inside the 60-second window.
    pub async fn shutdown(&self) -> Result<u32, ApiError> {
        self.publish_all(true).await
    }

    async fn publish_all(&self, force: bool) -> Result<u32, ApiError> {
        let mut count = 0u32;
        for status in ["active", "deleting", "shredded"] {
            for workspace in self.store.workspaces_with_status(status).await? {
                if self.publish_one(workspace.id, force).await? {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    async fn ensure_anchor_fresh(&self, workspace_id: Uuid) -> Result<(), ApiError> {
        let _ = self.publish_one(workspace_id, false).await?;
        let now = self.clock.unix_secs();
        let track = self.anchor_track.lock().expect("anchor lock");
        if let Some(since) = track.failed_since {
            if now.saturating_sub(since) > track.max_lag {
                return Err(ApiError::AuditAnchorUnavailable);
            }
        }
        Ok(())
    }

    async fn publish_one(&self, workspace_id: Uuid, force: bool) -> Result<bool, ApiError> {
        let Some((seq, tip_hash)) = self.store.audit_tip(workspace_id).await? else {
            return Ok(false);
        };
        let previous = self.store.latest_checkpoint(workspace_id).await?;
        if previous
            .as_ref()
            .is_some_and(|row| row.seq == seq && row.anchored_at.is_some())
        {
            return Ok(false);
        }
        let now = self.clock.unix_secs();
        let due = {
            let track = self.anchor_track.lock().expect("anchor lock");
            let last = track
                .last_checkpoint_at
                .get(&workspace_id)
                .copied()
                .unwrap_or(track.started_at);
            let gap = seq.saturating_sub(previous.as_ref().map(|row| row.seq).unwrap_or(0));
            force
                || gap >= CHECKPOINT_EVERY_EVENTS
                || now.saturating_sub(last) >= CHECKPOINT_EVERY_SECS
        };
        if !due {
            return Ok(false);
        }
        let message = checkpoint_message(workspace_id, seq, &tip_hash);
        let signature = self.signer.sign_message(&message);
        match self
            .anchor
            .put(workspace_id, seq, &tip_hash, &signature)
            .await
        {
            Ok(()) => {
                self.store
                    .insert_checkpoint(crate::store::CheckpointRow {
                        workspace_id,
                        seq,
                        tip_hash,
                        kid: self.signer.kid.clone(),
                        signature,
                        anchored_at: Some(now),
                    })
                    .await?;
                let mut track = self.anchor_track.lock().expect("anchor lock");
                track.last_checkpoint_at.insert(workspace_id, now);
                track.failed_since = None;
                Ok(true)
            }
            Err(_) => {
                let mut track = self.anchor_track.lock().expect("anchor lock");
                if track.failed_since.is_none() {
                    track.failed_since = Some(now);
                }
                Ok(false)
            }
        }
    }

    fn cached_kek(&self, workspace: &WorkspaceRow, kek_id: Uuid) -> Option<ZeroizingBuf<[u8; 32]>> {
        let cache = self.kek_cache.lock().expect("cache lock");
        let hit = cache.get(&kek_id)?;
        if hit.expires > Instant::now()
            && hit.workspace_id == workspace.id
            && workspace.status == "active"
        {
            Some(hit.key.clone())
        } else {
            None
        }
    }

    fn unwrap_kek(
        &self,
        workspace: &WorkspaceRow,
        kek: &KekRow,
    ) -> Result<ZeroizingBuf<[u8; 32]>, ApiError> {
        if !self.unwrap_secrets {
            return Err(ApiError::DecryptFailed);
        }
        if workspace.status != "active" {
            return Err(ApiError::WorkspaceDeleting);
        }
        if let Some(hit) = self.cached_kek(workspace, kek.id) {
            return Ok(hit);
        }
        let gate = {
            let mut flights = self.kek_flight.lock().expect("cache lock");
            flights
                .entry(kek.id)
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _flight = gate.lock().expect("kek flight");
        if let Some(hit) = self.cached_kek(workspace, kek.id) {
            return Ok(hit);
        }
        let context = KekContext {
            workspace_id: workspace.id,
            kek_id: kek.id,
            kek_version: kek.version,
        };
        let plain = self
            .kms
            .decrypt(&workspace.kms_key_ref, &kek.wrapped_kek, &context)
            .map_err(map_crypto)?;
        if plain.len() != 32 {
            return Err(ApiError::DecryptFailed);
        }
        let mut key = ZeroizingBuf::new([0u8; 32]);
        key.copy_from_slice(&plain);
        self.kek_cache.lock().expect("cache lock").insert(
            kek.id,
            CachedKek {
                workspace_id: workspace.id,
                key: key.clone(),
                expires: Instant::now() + KEK_CACHE_TTL,
            },
        );
        Ok(key)
    }

    fn audit(
        &self,
        workspace_id: Uuid,
        agent_id: Option<Uuid>,
        event_type: &str,
        fields: Vec<(String, AuditValue)>,
    ) -> AuditDraft {
        AuditDraft {
            workspace_id,
            agent_id,
            event_type: event_type.to_owned(),
            occurred_at_nanos: self.clock.unix_nanos(),
            fields,
        }
    }

    async fn audit_or_fail(
        &self,
        workspace_id: Uuid,
        agent_id: Option<Uuid>,
        event_type: &str,
        fields: Vec<(String, AuditValue)>,
    ) -> Result<(), ApiError> {
        self.store
            .append_audit(self.audit(workspace_id, agent_id, event_type, fields))
            .await
            .map(|_| ())
    }

    pub async fn purge_dpop(&self) -> Result<(), ApiError> {
        self.store.purge_dpop(self.clock.unix_secs()).await
    }

    pub async fn resume_rewrap_jobs(&self) -> Result<u64, ApiError> {
        let mut total = 0u64;
        for job in self.store.pending_rewrap_jobs().await? {
            let workspace = self.store.workspace(job.workspace_id).await?;
            let wrapped = self
                .rewrap_between(&workspace, job.from_kek_id, job.to_kek_id)
                .await?;
            self.store
                .finish_rewrap_job(job.id, "done", wrapped)
                .await?;
            total += wrapped;
        }
        Ok(total)
    }
}

fn access_fields(
    secret: &SecretRow,
    version: Option<Uuid>,
    delivery: Delivery,
    host: Option<&str>,
) -> Vec<(String, AuditValue)> {
    let mut fields = vec![
        ("secret_id".into(), AuditValue::Uuid(secret.id)),
        (
            "secret_name".into(),
            AuditValue::String(secret.name.clone()),
        ),
        (
            "delivery".into(),
            AuditValue::String(delivery.as_str().to_owned()),
        ),
    ];
    if let Some(version) = version {
        fields.push(("version_id".into(), AuditValue::Uuid(version)));
    }
    if let Some(host) = host {
        fields.push(("upstream_host".into(), AuditValue::String(host.to_owned())));
    }
    fields
}

fn random_32() -> Result<[u8; 32], ApiError> {
    let mut buf = [0u8; 32];
    random_bytes(&mut buf).map_err(|_| ApiError::KmsUnavailable)?;
    Ok(buf)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

fn map_crypto(err: credentials_crypto::CryptoError) -> ApiError {
    match err {
        credentials_crypto::CryptoError::RootKeyUnavailable
        | credentials_crypto::CryptoError::DevProviderInProduction => ApiError::KmsUnavailable,
        credentials_crypto::CryptoError::SecretLength => ApiError::PayloadTooLarge,
        _ => ApiError::DecryptFailed,
    }
}

/// Re-export so callers can build a DPoP key without reaching into the module.
pub fn generate_dpop() -> Result<DpopKey, ApiError> {
    DpopKey::generate()
}
