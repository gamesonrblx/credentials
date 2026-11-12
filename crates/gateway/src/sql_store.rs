//! SQLite and Postgres behind one [`Store`].
//!
//! Queries are runtime strings, not `sqlx::query!`, so this crate compiles
//! without a live database. Postgres placeholders are `$1` style. SQLite uses
//! `?`. Migrations live in `migrations/{sqlite,postgres}` and run on connect.
//!
//! Postgres links rustls with the aws-lc-rs provider. The URL is passed to
//! sqlx unchanged: an explicit `sslmode` is honoured and a missing one takes
//! the sqlx default (`prefer`). [`SqlStore::postgres_url_enforces_tls`] tells
//! production startup whether the URL refuses a plaintext connection.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use credentials_crypto::SealedSecret;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Pool, Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::audit::{commit_event, AuditDraft, AuditRecord, AuditValue};
use crate::policy::DeliveryPolicy;
use crate::store::{
    ensure_recipient, ensure_stored, AgentRow, CheckpointRow, KekRow, RecipientRow, RewrapJobRow,
    SecretRow, SessionRow, Store, VersionRow, WorkspaceKeyRow, WorkspaceRow, WrapMode,
};
use crate::ApiError;

macro_rules! on_pool {
    ($self:expr, $sql:expr, |$db:ident, $q:ident| $body:block) => {{
        match &$self.pool {
            SqlPool::Sqlite(pool) => {
                let $db = pool;
                let $q: &str = $sql;
                $body
            }
            SqlPool::Postgres(pool) => {
                let $db = pool;
                let owned = pg_placeholders($sql);
                let $q: &str = &owned;
                $body
            }
        }
    }};
}

macro_rules! on_tx {
    ($tx:expr, $sql:expr, |$db:ident, $q:ident| $body:block) => {{
        match $tx {
            SqlTx::Sqlite($db) => {
                let $q: &str = $sql;
                $body
            }
            SqlTx::Postgres($db) => {
                let owned = pg_placeholders($sql);
                let $q: &str = &owned;
                $body
            }
        }
    }};
}

macro_rules! workspace_from {
    ($row:expr) => {{
        let hash: Option<Vec<u8>> = $row.try_get("credential_hash").map_err(map_db)?;
        let delete_after: Option<i64> = $row.try_get("delete_after").map_err(map_db)?;
        Ok(WorkspaceRow {
            id: $row.try_get("id").map_err(map_db)?,
            status: $row.try_get("status").map_err(map_db)?,
            kms_key_ref: $row.try_get("kms_key_ref").map_err(map_db)?,
            credential_hash: hash.map(arr32).transpose()?.unwrap_or([0u8; 32]),
            audit_seq: u64_from($row.try_get("audit_seq").map_err(map_db)?)?,
            delete_after: delete_after.map(u64_from).transpose()?,
        })
    }};
}
macro_rules! kek_from {
    ($row:expr) => {{
        let wrapped: Option<Vec<u8>> = $row.try_get("wrapped_kek").map_err(map_db)?;
        let version: i32 = $row.try_get("version").map_err(map_db)?;
        Ok(KekRow {
            id: $row.try_get("id").map_err(map_db)?,
            workspace_id: $row.try_get("workspace_id").map_err(map_db)?,
            version: u32::try_from(version).map_err(|_| ApiError::StoreUnavailable)?,
            status: $row.try_get("status").map_err(map_db)?,
            wrapped_kek: wrapped.unwrap_or_default(),
            kms_key_ref: $row.try_get("kms_key_ref").map_err(map_db)?,
        })
    }};
}
macro_rules! secret_from {
    ($row:expr) => {{
        let hosts: String = $row.try_get("hosts").map_err(map_db)?;
        Ok(SecretRow {
            id: $row.try_get("id").map_err(map_db)?,
            workspace_id: $row.try_get("workspace_id").map_err(map_db)?,
            name: $row.try_get("name").map_err(map_db)?,
            status: $row.try_get("status").map_err(map_db)?,
            policy: DeliveryPolicy {
                header_name: $row.try_get("header_name").map_err(map_db)?,
                header_format: $row.try_get("header_format").map_err(map_db)?,
                env_name: $row.try_get("env_name").map_err(map_db)?,
                hosts: serde_json::from_str(&hosts).map_err(|_| ApiError::StoreUnavailable)?,
                allow_proxy: $row.try_get("allow_proxy").map_err(map_db)?,
                allow_header: $row.try_get("allow_header").map_err(map_db)?,
                allow_env: $row.try_get("allow_env").map_err(map_db)?,
            },
        })
    }};
}
macro_rules! version_from {
    ($row:expr) => {{
        let version: i32 = $row.try_get("version").map_err(map_db)?;
        let len: i32 = $row.try_get("plaintext_len").map_err(map_db)?;
        let mode: String = $row.try_get("wrap_mode").map_err(map_db)?;
        Ok(VersionRow {
            id: $row.try_get("id").map_err(map_db)?,
            secret_id: $row.try_get("secret_id").map_err(map_db)?,
            workspace_id: $row.try_get("workspace_id").map_err(map_db)?,
            version: u32::try_from(version).map_err(|_| ApiError::StoreUnavailable)?,
            sealed: SealedSecret {
                payload_alg: $row.try_get("payload_alg").map_err(map_db)?,
                payload_nonce: arr12(
                    $row.try_get::<Vec<u8>, _>("payload_nonce")
                        .map_err(map_db)?,
                )?,
                payload_ciphertext: $row.try_get("payload_ciphertext").map_err(map_db)?,
                dek_wrap_alg: $row.try_get("dek_wrap_alg").map_err(map_db)?,
                dek_wrap_nonce: arr12(
                    $row.try_get::<Vec<u8>, _>("dek_wrap_nonce")
                        .map_err(map_db)?,
                )?,
                dek_wrapped: $row.try_get("dek_wrapped").map_err(map_db)?,
                plaintext_len: usize::try_from(len).map_err(|_| ApiError::StoreUnavailable)?,
            },
            kek_id: $row.try_get("kek_id").map_err(map_db)?,
            wrap_mode: WrapMode::parse(&mode)?,
            e2e_encapsulation: $row.try_get("e2e_encapsulation").map_err(map_db)?,
        })
    }};
}
macro_rules! session_from {
    ($row:expr) => {{
        let scopes: String = $row.try_get("scopes").map_err(map_db)?;
        let revoked: Option<i64> = $row.try_get("revoked_at").map_err(map_db)?;
        Ok(SessionRow {
            id: $row.try_get("id").map_err(map_db)?,
            workspace_id: $row.try_get("workspace_id").map_err(map_db)?,
            agent_id: $row.try_get("agent_id").map_err(map_db)?,
            dpop_jkt: $row.try_get("dpop_jkt").map_err(map_db)?,
            scopes: serde_json::from_str(&scopes).map_err(|_| ApiError::StoreUnavailable)?,
            expires_at: u64_from($row.try_get("expires_at").map_err(map_db)?)?,
            revoked_at: revoked.map(u64_from).transpose()?,
            token_jti: $row.try_get("token_jti").map_err(map_db)?,
        })
    }};
}
macro_rules! audit_from {
    ($row:expr) => {{
        let payload: String = $row.try_get("payload").map_err(map_db)?;
        let fields: Vec<(String, AuditValue)> =
            serde_json::from_str(&payload).map_err(|_| ApiError::StoreUnavailable)?;
        let agent_seq: Option<i64> = $row.try_get("agent_seq").map_err(map_db)?;
        let agent_prev: Option<Vec<u8>> = $row.try_get("agent_prev_hash").map_err(map_db)?;
        let agent_hash: Option<Vec<u8>> = $row.try_get("agent_hash").map_err(map_db)?;
        Ok(AuditRecord {
            workspace_id: $row.try_get("workspace_id").map_err(map_db)?,
            seq: u64_from($row.try_get("seq").map_err(map_db)?)?,
            agent_id: $row.try_get("agent_id").map_err(map_db)?,
            agent_seq: agent_seq.map(u64_from).transpose()?.unwrap_or(0),
            event_type: $row.try_get("event_type").map_err(map_db)?,
            occurred_at_nanos: u64_from($row.try_get("occurred_at").map_err(map_db)?)?,
            fields,
            prev_hash: arr32($row.try_get::<Vec<u8>, _>("prev_hash").map_err(map_db)?)?,
            hash: arr32($row.try_get::<Vec<u8>, _>("hash").map_err(map_db)?)?,
            agent_prev_hash: agent_prev.map(arr32).transpose()?.unwrap_or([0u8; 32]),
            agent_hash: agent_hash.map(arr32).transpose()?,
        })
    }};
}

fn pg_placeholders(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut n = 1u32;
    for ch in sql.chars() {
        if ch == '?' {
            out.push('$');
            out.push_str(&n.to_string());
            n += 1;
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_postgres(url: &str) -> bool {
    url.starts_with("postgres://") || url.starts_with("postgresql://")
}

/// The `sslmode` values that refuse a plaintext connection.
const TLS_SSLMODES: &[&str] = &["require", "verify-ca", "verify-full"];

fn map_db(err: sqlx::Error) -> ApiError {
    if let Some(db) = err.as_database_error() {
        if db.is_unique_violation() {
            return ApiError::BadRequest;
        }
        if db.is_foreign_key_violation() {
            return ApiError::NotFound;
        }
        tracing::error!(code = ?db.code(), "store request failed");
    } else {
        tracing::error!("store request failed");
    }
    ApiError::StoreUnavailable
}

fn map_migrate(err: sqlx::migrate::MigrateError) -> ApiError {
    tracing::error!(error = %err, "schema migration failed");
    ApiError::StoreUnavailable
}

fn now_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn i64_from(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::StoreUnavailable)
}

fn u64_from(value: i64) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| ApiError::StoreUnavailable)
}

fn arr32(bytes: Vec<u8>) -> Result<[u8; 32], ApiError> {
    bytes.try_into().map_err(|_| ApiError::DecryptFailed)
}

fn arr12(bytes: Vec<u8>) -> Result<[u8; 12], ApiError> {
    bytes.try_into().map_err(|_| ApiError::DecryptFailed)
}

enum SqlPool {
    Sqlite(Pool<Sqlite>),
    Postgres(Pool<Postgres>),
}

enum SqlTx<'a> {
    Sqlite(Transaction<'a, Sqlite>),
    Postgres(Transaction<'a, Postgres>),
}

pub struct SqlStore {
    pool: SqlPool,
}

impl SqlStore {
    pub async fn connect(url: &str) -> Result<Self, ApiError> {
        let pool = if is_postgres(url) {
            let pool = PgPoolOptions::new()
                .max_connections(8)
                .connect(url)
                .await
                .map_err(map_db)?;
            sqlx::migrate!("./migrations/postgres")
                .run(&pool)
                .await
                .map_err(map_migrate)?;
            SqlPool::Postgres(pool)
        } else if url.starts_with("sqlite:") {
            let options = SqliteConnectOptions::from_str(url)
                .map_err(|_| ApiError::StoreUnavailable)?
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Delete)
                .synchronous(SqliteSynchronous::Full)
                .busy_timeout(Duration::from_secs(5));
            let pool = SqlitePoolOptions::new()
                .max_connections(4)
                .connect_with(options)
                .await
                .map_err(map_db)?;
            sqlx::migrate!("./migrations/sqlite")
                .run(&pool)
                .await
                .map_err(map_migrate)?;
            SqlPool::Sqlite(pool)
        } else {
            return Err(ApiError::StoreUnavailable);
        };
        Ok(Self { pool })
    }

    /// True when a Postgres URL sets `sslmode` to `require`, `verify-ca` or
    /// `verify-full`. A missing `sslmode`, a weaker one, or a repeated key
    /// with any weaker value is false. Production refuses such a URL.
    pub fn postgres_url_enforces_tls(url: &str) -> bool {
        if !is_postgres(url) {
            return false;
        }
        let Ok(parsed) = url::Url::parse(url) else {
            return false;
        };
        let modes: Vec<String> = parsed
            .query_pairs()
            .filter(|(key, _)| key == "sslmode")
            .map(|(_, value)| value.into_owned())
            .collect();
        !modes.is_empty()
            && modes
                .iter()
                .all(|mode| TLS_SSLMODES.contains(&mode.as_str()))
    }

    pub fn engine_name(&self) -> &'static str {
        match self.pool {
            SqlPool::Sqlite(_) => "sqlite",
            SqlPool::Postgres(_) => "postgres",
        }
    }

    async fn begin(&self) -> Result<SqlTx<'_>, ApiError> {
        match &self.pool {
            SqlPool::Sqlite(pool) => Ok(SqlTx::Sqlite(
                pool.begin_with("BEGIN IMMEDIATE").await.map_err(map_db)?,
            )),
            SqlPool::Postgres(pool) => Ok(SqlTx::Postgres(pool.begin().await.map_err(map_db)?)),
        }
    }
}

async fn commit(tx: SqlTx<'_>) -> Result<(), ApiError> {
    match tx {
        SqlTx::Sqlite(tx) => tx.commit().await.map_err(map_db)?,
        SqlTx::Postgres(tx) => tx.commit().await.map_err(map_db)?,
    }
    Ok(())
}

#[async_trait]
impl Store for SqlStore {
    async fn insert_workspace(&self, row: WorkspaceRow, kek: KekRow) -> Result<(), ApiError> {
        let mut tx = self.begin().await?;
        let created = now_nanos();
        on_tx!(&mut tx, "INSERT INTO workspaces (id, status, kms_key_ref, audit_seq, created_at) VALUES (?, ?, ?, ?, ?)", |db, q| {
            sqlx::query(q)
                .bind(row.id)
                .bind(&row.status)
                .bind(&row.kms_key_ref)
                .bind(i64_from(row.audit_seq)?)
                .bind(created)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        });
        on_tx!(&mut tx, "INSERT INTO workspace_credentials (id, workspace_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", |db, q| {
            sqlx::query(q)
                .bind(Uuid::now_v7())
                .bind(row.id)
                .bind(row.credential_hash.as_slice())
                .bind(created)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        });
        insert_kek_tx(&mut tx, &kek, created).await?;
        commit(tx).await
    }

    async fn workspace_by_hash(&self, hash: &[u8; 32]) -> Result<WorkspaceRow, ApiError> {
        let sql =
            "SELECT w.id, w.status, w.kms_key_ref, w.audit_seq, w.delete_after, c.secret_hash AS credential_hash \
                   FROM workspace_credentials c \
                   JOIN workspaces w ON w.id = c.workspace_id \
                   WHERE c.secret_hash = ? AND c.revoked_at IS NULL";
        on_pool!(self, sql, |db, q| {
            let row = sqlx::query(q)
                .bind(hash.as_slice())
                .fetch_optional(db)
                .await
                .map_err(map_db)?;
            match row {
                Some(row) => workspace_from!(&row),
                None => Err(ApiError::Unauthenticated),
            }
        })
    }

    async fn workspace(&self, id: Uuid) -> Result<WorkspaceRow, ApiError> {
        let sql = "SELECT w.id, w.status, w.kms_key_ref, w.audit_seq, w.delete_after, \
                   (SELECT c.secret_hash FROM workspace_credentials c \
                    WHERE c.workspace_id = w.id AND c.revoked_at IS NULL \
                    ORDER BY c.created_at LIMIT 1) AS credential_hash \
                   FROM workspaces w WHERE w.id = ?";
        on_pool!(self, sql, |db, q| {
            let row = sqlx::query(q)
                .bind(id)
                .fetch_optional(db)
                .await
                .map_err(map_db)?;
            match row {
                Some(row) => workspace_from!(&row),
                None => Err(ApiError::NotFound),
            }
        })
    }

    async fn set_workspace_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE workspaces SET status = ? WHERE id = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(status)
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn schedule_workspace_deletion(
        &self,
        id: Uuid,
        delete_after: u64,
    ) -> Result<(), ApiError> {
        let deadline = i64_from(delete_after)?;
        let changed = on_pool!(
            self,
            "UPDATE workspaces SET status = 'deleting', delete_after = ? WHERE id = ? AND status = 'active'",
            |db, q| {
                sqlx::query(q)
                    .bind(deadline)
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::WorkspaceDeleting)
        } else {
            Ok(())
        }
    }

    async fn cancel_workspace_deletion(&self, id: Uuid) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE workspaces SET status = 'active', delete_after = NULL WHERE id = ? AND status = 'deleting'",
            |db, q| {
                sqlx::query(q)
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::BadRequest)
        } else {
            Ok(())
        }
    }

    async fn rotate_workspace_credential(
        &self,
        workspace_id: Uuid,
        old_hash: &[u8; 32],
        new_hash: [u8; 32],
        at: u64,
        audit: AuditDraft,
    ) -> Result<(), ApiError> {
        let stamped = i64_from(at)?;
        let mut tx = self.begin().await?;
        append_tx(&mut tx, audit).await?;
        let changed = on_tx!(&mut tx, "UPDATE workspace_credentials SET revoked_at = ? WHERE workspace_id = ? AND secret_hash = ? AND revoked_at IS NULL", |db, q| {
            sqlx::query(q)
                .bind(stamped)
                .bind(workspace_id)
                .bind(old_hash.as_slice())
                .execute(&mut **db)
                .await
                .map_err(map_db)?
                .rows_affected()
        });
        if changed != 1 {
            return Err(ApiError::Unauthenticated);
        }
        on_tx!(&mut tx, "INSERT INTO workspace_credentials (id, workspace_id, secret_hash, created_at) VALUES (?, ?, ?, ?)", |db, q| {
            sqlx::query(q)
                .bind(Uuid::now_v7())
                .bind(workspace_id)
                .bind(new_hash.as_slice())
                .bind(now_nanos())
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        });
        commit(tx).await
    }

    async fn insert_kek(&self, kek: KekRow) -> Result<(), ApiError> {
        let mut tx = self.begin().await?;
        insert_kek_tx(&mut tx, &kek, now_nanos()).await?;
        commit(tx).await
    }

    async fn swap_active_kek(&self, old_id: Uuid, new_kek: KekRow) -> Result<(), ApiError> {
        if new_kek.status != "active" {
            return Err(ApiError::BadRequest);
        }
        let mut tx = self.begin().await?;
        let changed = on_tx!(&mut tx, "UPDATE kek_versions SET status = 'decrypt_only' WHERE id = ? AND workspace_id = ? AND status = 'active'", |db, q| {
            sqlx::query(q)
                .bind(old_id)
                .bind(new_kek.workspace_id)
                .execute(&mut **db)
                .await
                .map_err(map_db)?
                .rows_affected()
        });
        if changed != 1 {
            return Err(ApiError::BadRequest);
        }
        insert_kek_tx(&mut tx, &new_kek, now_nanos()).await?;
        commit(tx).await
    }

    async fn active_kek(&self, workspace_id: Uuid) -> Result<KekRow, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, version, status, wrapped_kek, kms_key_ref FROM kek_versions WHERE workspace_id = ? AND status = 'active'",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                match row {
                    Some(row) => kek_from!(&row),
                    None => Err(ApiError::KmsUnavailable),
                }
            }
        )
    }

    async fn kek(&self, id: Uuid) -> Result<KekRow, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, version, status, wrapped_kek, kms_key_ref FROM kek_versions WHERE id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                match row {
                    Some(row) => kek_from!(&row),
                    None => Err(ApiError::KmsUnavailable),
                }
            }
        )
    }

    async fn list_keks(&self, workspace_id: Uuid) -> Result<Vec<KekRow>, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, version, status, wrapped_kek, kms_key_ref FROM kek_versions WHERE workspace_id = ? ORDER BY version",
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter().map(|row| kek_from!(row)).collect()
            }
        )
    }

    async fn set_kek_status(&self, id: Uuid, status: &str) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE kek_versions SET status = ? WHERE id = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(status)
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn next_kek_version(&self, workspace_id: Uuid) -> Result<u32, ApiError> {
        on_pool!(
            self,
            "SELECT COALESCE(MAX(version), 0) AS version FROM kek_versions WHERE workspace_id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_one(db)
                    .await
                    .map_err(map_db)?;
                let version: i32 = row.try_get("version").map_err(map_db)?;
                u32::try_from(version.saturating_add(1)).map_err(|_| ApiError::StoreUnavailable)
            }
        )
    }

    async fn insert_agent(&self, row: AgentRow) -> Result<(), ApiError> {
        on_pool!(
            self,
            "INSERT INTO agents (id, workspace_id, display_name, status, created_at) VALUES (?, ?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(row.id)
                    .bind(row.workspace_id)
                    .bind(&row.display_name)
                    .bind(&row.status)
                    .bind(now_nanos())
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        Ok(())
    }

    async fn agent(&self, id: Uuid) -> Result<AgentRow, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, display_name, status FROM agents WHERE id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Err(ApiError::NotFound);
                };
                Ok(AgentRow {
                    id: row.try_get("id").map_err(map_db)?,
                    workspace_id: row.try_get("workspace_id").map_err(map_db)?,
                    display_name: row.try_get("display_name").map_err(map_db)?,
                    status: row.try_get("status").map_err(map_db)?,
                })
            }
        )
    }

    async fn insert_session(&self, row: SessionRow) -> Result<(), ApiError> {
        let scopes = serde_json::to_string(&row.scopes).map_err(|_| ApiError::StoreUnavailable)?;
        on_pool!(
            self,
            "INSERT INTO agent_sessions (id, workspace_id, agent_id, dpop_jkt, scopes, expires_at, revoked_at, token_jti) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(row.id)
                    .bind(row.workspace_id)
                    .bind(row.agent_id)
                    .bind(&row.dpop_jkt)
                    .bind(&scopes)
                    .bind(i64_from(row.expires_at)?)
                    .bind(row.revoked_at.map(i64_from).transpose()?)
                    .bind(row.token_jti)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        Ok(())
    }

    async fn session(&self, id: Uuid) -> Result<SessionRow, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, agent_id, dpop_jkt, scopes, expires_at, revoked_at, token_jti FROM agent_sessions WHERE id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Err(ApiError::Unauthenticated);
                };
                session_from!(&row)
            }
        )
    }

    async fn revoke_session(&self, id: Uuid, at: u64) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE agent_sessions SET revoked_at = ? WHERE id = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(i64_from(at)?)
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn insert_secret(
        &self,
        secret: SecretRow,
        version: VersionRow,
        audit: AuditDraft,
    ) -> Result<(), ApiError> {
        ensure_stored(&version)?;
        let mut tx = self.begin().await?;
        append_tx(&mut tx, audit).await?;
        let created = now_nanos();
        on_tx!(&mut tx, "INSERT INTO secrets (id, workspace_id, name, status, created_at) VALUES (?, ?, ?, ?, ?)", |db, q| {
            sqlx::query(q)
                .bind(secret.id)
                .bind(secret.workspace_id)
                .bind(&secret.name)
                .bind(&secret.status)
                .bind(created)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        });
        insert_policy_tx(&mut tx, secret.id, &secret.policy).await?;
        insert_version_tx(&mut tx, &version, created).await?;
        commit(tx).await
    }

    async fn insert_version(&self, version: VersionRow, audit: AuditDraft) -> Result<(), ApiError> {
        ensure_stored(&version)?;
        let mut tx = self.begin().await?;
        append_tx(&mut tx, audit).await?;
        insert_version_tx(&mut tx, &version, now_nanos()).await?;
        commit(tx).await
    }

    async fn secret_by_name(&self, workspace_id: Uuid, name: &str) -> Result<SecretRow, ApiError> {
        let sql = "SELECT s.id, s.workspace_id, s.name, s.status, p.header_name, p.header_format, p.env_name, p.hosts, p.allow_proxy, p.allow_header, p.allow_env \
                   FROM secrets s JOIN secret_delivery_policies p ON p.secret_id = s.id \
                   WHERE s.workspace_id = ? AND s.name = ?";
        on_pool!(self, sql, |db, q| {
            let row = sqlx::query(q)
                .bind(workspace_id)
                .bind(name)
                .fetch_optional(db)
                .await
                .map_err(map_db)?;
            match row {
                Some(row) => secret_from!(&row),
                None => Err(ApiError::NotFound),
            }
        })
    }

    async fn latest_version(&self, secret_id: Uuid) -> Result<VersionRow, ApiError> {
        on_pool!(
            self,
            &format!("{VERSION_COLS} WHERE secret_id = ? ORDER BY version DESC LIMIT 1"),
            |db, q| {
                let row = sqlx::query(q)
                    .bind(secret_id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                match row {
                    Some(row) => version_from!(&row),
                    None => Err(ApiError::NotFound),
                }
            }
        )
    }

    async fn versions_for_kek(&self, kek_id: Uuid) -> Result<Vec<VersionRow>, ApiError> {
        on_pool!(
            self,
            &format!("{VERSION_COLS} WHERE kek_id = ? ORDER BY version"),
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(kek_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter().map(|row| version_from!(row)).collect()
            }
        )
    }

    async fn update_wrap(
        &self,
        version_id: Uuid,
        expected_kek: Uuid,
        sealed: SealedSecret,
        new_kek: Uuid,
    ) -> Result<bool, ApiError> {
        let mut tx = self.begin().await?;
        let current = on_tx!(
            &mut tx,
            "SELECT kek_id, wrap_mode FROM secret_versions WHERE id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(version_id)
                    .fetch_optional(&mut **db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Err(ApiError::NotFound);
                };
                let mode = WrapMode::parse(
                    row.try_get::<String, _>("wrap_mode")
                        .map_err(map_db)?
                        .as_str(),
                )?;
                if mode != WrapMode::Gateway {
                    return Err(ApiError::BadRequest);
                }
                let current: Uuid = row.try_get("kek_id").map_err(map_db)?;
                Ok(current)
            }
        )?;
        if current != expected_kek {
            commit(tx).await?;
            return Ok(false);
        }
        on_tx!(
            &mut tx,
            "UPDATE secret_versions SET dek_wrap_alg = ?, dek_wrap_nonce = ?, dek_wrapped = ?, kek_id = ? WHERE id = ? AND kek_id = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(&sealed.dek_wrap_alg)
                    .bind(sealed.dek_wrap_nonce.as_slice())
                    .bind(sealed.dek_wrapped.as_slice())
                    .bind(new_kek)
                    .bind(version_id)
                    .bind(expected_kek)
                    .execute(&mut **db)
                    .await
                    .map_err(map_db)?;
            }
        );
        commit(tx).await?;
        Ok(true)
    }

    async fn append_audit(&self, draft: AuditDraft) -> Result<AuditRecord, ApiError> {
        let mut tx = self.begin().await?;
        let record = append_tx(&mut tx, draft).await?;
        commit(tx).await?;
        Ok(record)
    }

    async fn audit_for_workspace(&self, workspace_id: Uuid) -> Result<Vec<AuditRecord>, ApiError> {
        on_pool!(
            self,
            &format!("{AUDIT_COLS} WHERE workspace_id = ? ORDER BY seq"),
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter().map(|row| audit_from!(row)).collect()
            }
        )
    }

    async fn audit_for_agent(
        &self,
        workspace_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Vec<AuditRecord>, ApiError> {
        on_pool!(
            self,
            &format!("{AUDIT_COLS} WHERE workspace_id = ? AND agent_id = ? ORDER BY agent_seq"),
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(workspace_id)
                    .bind(agent_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter().map(|row| audit_from!(row)).collect()
            }
        )
    }

    async fn audit_page(
        &self,
        workspace_id: Uuid,
        agent_id: Option<Uuid>,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, ApiError> {
        let after = i64_from(after_seq)?;
        let limit = i64::from(limit);
        match agent_id {
            Some(agent) => on_pool!(
                self,
                &format!("{AUDIT_COLS} WHERE workspace_id = ? AND agent_id = ? AND seq > ? ORDER BY seq LIMIT ?"),
                |db, q| {
                    let rows = sqlx::query(q)
                        .bind(workspace_id)
                        .bind(agent)
                        .bind(after)
                        .bind(limit)
                        .fetch_all(db)
                        .await
                        .map_err(map_db)?;
                    rows.iter().map(|row| audit_from!(row)).collect()
                }
            ),
            None => on_pool!(
                self,
                &format!("{AUDIT_COLS} WHERE workspace_id = ? AND seq > ? ORDER BY seq LIMIT ?"),
                |db, q| {
                    let rows = sqlx::query(q)
                        .bind(workspace_id)
                        .bind(after)
                        .bind(limit)
                        .fetch_all(db)
                        .await
                        .map_err(map_db)?;
                    rows.iter().map(|row| audit_from!(row)).collect()
                }
            ),
        }
    }

    async fn audit_event(
        &self,
        workspace_id: Uuid,
        seq: u64,
    ) -> Result<Option<AuditRecord>, ApiError> {
        let seq = i64_from(seq)?;
        on_pool!(
            self,
            &format!("{AUDIT_COLS} WHERE workspace_id = ? AND seq = ?"),
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .bind(seq)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                match row {
                    Some(row) => {
                        let record: Result<AuditRecord, ApiError> = audit_from!(&row);
                        record.map(Some)
                    }
                    None => Ok(None),
                }
            }
        )
    }

    async fn revoke_workspace_sessions(&self, workspace_id: Uuid, at: u64) -> Result<(), ApiError> {
        on_pool!(
            self,
            "INSERT INTO revoked_jtis (jti, workspace_id, expires_at) SELECT token_jti, workspace_id, expires_at FROM agent_sessions WHERE workspace_id = ? AND token_jti IS NOT NULL AND revoked_at IS NULL",
            |db, q| {
                sqlx::query(q)
                    .bind(workspace_id)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        on_pool!(
            self,
            "UPDATE agent_sessions SET revoked_at = ? WHERE workspace_id = ? AND revoked_at IS NULL",
            |db, q| {
                sqlx::query(q)
                    .bind(i64_from(at)?)
                    .bind(workspace_id)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        Ok(())
    }

    async fn revoke_workspace_credentials(
        &self,
        workspace_id: Uuid,
        at: u64,
    ) -> Result<(), ApiError> {
        on_pool!(
            self,
            "UPDATE workspace_credentials SET revoked_at = ? WHERE workspace_id = ? AND revoked_at IS NULL",
            |db, q| {
                sqlx::query(q)
                    .bind(i64_from(at)?)
                    .bind(workspace_id)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        Ok(())
    }

    async fn delete_secret_material(&self, workspace_id: Uuid) -> Result<(), ApiError> {
        let mut tx = self.begin().await?;
        for sql in [
            "DELETE FROM secret_versions WHERE workspace_id = ?",
            "DELETE FROM secret_delivery_policies WHERE secret_id IN (SELECT id FROM secrets WHERE workspace_id = ?)",
            "DELETE FROM secrets WHERE workspace_id = ?",
            "DELETE FROM kek_versions WHERE workspace_id = ?",
        ] {
            on_tx!(&mut tx, sql, |db, q| {
                sqlx::query(q)
                    .bind(workspace_id)
                    .execute(&mut **db)
                    .await
                    .map_err(map_db)?;
            });
        }
        commit(tx).await
    }

    async fn workspaces_with_status(&self, status: &str) -> Result<Vec<WorkspaceRow>, ApiError> {
        let sql = "SELECT w.id, w.status, w.kms_key_ref, w.audit_seq, w.delete_after, \
                   (SELECT c.secret_hash FROM workspace_credentials c \
                    WHERE c.workspace_id = w.id AND c.revoked_at IS NULL \
                    ORDER BY c.created_at LIMIT 1) AS credential_hash \
                   FROM workspaces w WHERE w.status = ?";
        on_pool!(self, sql, |db, q| {
            let rows = sqlx::query(q)
                .bind(status)
                .fetch_all(db)
                .await
                .map_err(map_db)?;
            rows.iter().map(|row| workspace_from!(row)).collect()
        })
    }

    async fn audit_tip(&self, workspace_id: Uuid) -> Result<Option<(u64, [u8; 32])>, ApiError> {
        on_pool!(
            self,
            "SELECT seq, hash FROM audit_events WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let seq = u64_from(row.try_get("seq").map_err(map_db)?)?;
                let hash = arr32(row.try_get::<Vec<u8>, _>("hash").map_err(map_db)?)?;
                Ok(Some((seq, hash)))
            }
        )
    }

    async fn insert_checkpoint(&self, row: CheckpointRow) -> Result<(), ApiError> {
        on_pool!(
            self,
            "INSERT INTO audit_checkpoints (workspace_id, seq, tip_hash, kid, signature, anchored_at) VALUES (?, ?, ?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(row.workspace_id)
                    .bind(i64_from(row.seq)?)
                    .bind(row.tip_hash.as_slice())
                    .bind(&row.kid)
                    .bind(row.signature.as_slice())
                    .bind(row.anchored_at.map(i64_from).transpose()?)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
            }
        );
        Ok(())
    }

    async fn latest_checkpoint(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<CheckpointRow>, ApiError> {
        on_pool!(
            self,
            "SELECT workspace_id, seq, tip_hash, kid, signature, anchored_at FROM audit_checkpoints WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let anchored: Option<i64> = row.try_get("anchored_at").map_err(map_db)?;
                Ok(Some(CheckpointRow {
                    workspace_id: row.try_get("workspace_id").map_err(map_db)?,
                    seq: u64_from(row.try_get("seq").map_err(map_db)?)?,
                    tip_hash: arr32(row.try_get::<Vec<u8>, _>("tip_hash").map_err(map_db)?)?,
                    kid: row.try_get("kid").map_err(map_db)?,
                    signature: row.try_get("signature").map_err(map_db)?,
                    anchored_at: anchored.map(u64_from).transpose()?,
                }))
            }
        )
    }

    async fn set_secret_status(
        &self,
        workspace_id: Uuid,
        name: &str,
        status: &str,
    ) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE secrets SET status = ? WHERE workspace_id = ? AND name = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(status)
                    .bind(workspace_id)
                    .bind(name)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn list_sessions(&self, workspace_id: Uuid) -> Result<Vec<SessionRow>, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, agent_id, dpop_jkt, scopes, expires_at, revoked_at, token_jti FROM agent_sessions WHERE workspace_id = ?",
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter().map(|row| session_from!(row)).collect()
            }
        )
    }

    async fn insert_workspace_key(&self, row: WorkspaceKeyRow) -> Result<(), ApiError> {
        if row.encapsulation_key.len() != credentials_crypto::E2E_ENCAPSULATION_KEY_LEN {
            return Err(ApiError::BadRequest);
        }
        let created = now_nanos();
        on_pool!(
            self,
            "INSERT INTO workspace_keys (id, workspace_id, encapsulation_key, created_at) VALUES (?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(row.id)
                    .bind(row.workspace_id)
                    .bind(row.encapsulation_key.as_slice())
                    .bind(created)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                Ok(())
            }
        )
    }

    async fn workspace_key(&self, workspace_id: Uuid) -> Result<WorkspaceKeyRow, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, encapsulation_key FROM workspace_keys WHERE workspace_id = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?
                    .ok_or(ApiError::NotFound)?;
                Ok(WorkspaceKeyRow {
                    id: row.try_get("id").map_err(map_db)?,
                    workspace_id: row.try_get("workspace_id").map_err(map_db)?,
                    encapsulation_key: row.try_get("encapsulation_key").map_err(map_db)?,
                })
            }
        )
    }

    async fn insert_recipient(&self, row: RecipientRow) -> Result<(), ApiError> {
        ensure_recipient(&row)?;
        let created = now_nanos();
        on_pool!(
            self,
            "INSERT INTO recovery_recipients (id, workspace_id, kind, encapsulation_key, encapsulation, prf_salt, kdf_params, wrap_nonce, wrapped_key, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(row.id)
                    .bind(row.workspace_id)
                    .bind(&row.kind)
                    .bind(row.encapsulation_key.as_deref())
                    .bind(row.encapsulation.as_deref())
                    .bind(row.prf_salt.as_deref())
                    .bind(&row.kdf_params)
                    .bind(row.wrap_nonce.as_slice())
                    .bind(row.wrapped_key.as_slice())
                    .bind(created)
                    .bind(row.revoked_at.map(|at| i64::try_from(at).unwrap_or(0)))
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                Ok(())
            }
        )
    }

    async fn list_recipients(&self, workspace_id: Uuid) -> Result<Vec<RecipientRow>, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, kind, encapsulation_key, encapsulation, prf_salt, kdf_params, wrap_nonce, wrapped_key, revoked_at FROM recovery_recipients WHERE workspace_id = ?",
            |db, q| {
                let rows = sqlx::query(q)
                    .bind(workspace_id)
                    .fetch_all(db)
                    .await
                    .map_err(map_db)?;
                rows.iter()
                    .map(|row| {
                        let revoked: Option<i64> = row.try_get("revoked_at").map_err(map_db)?;
                        Ok(RecipientRow {
                            id: row.try_get("id").map_err(map_db)?,
                            workspace_id: row.try_get("workspace_id").map_err(map_db)?,
                            kind: row.try_get("kind").map_err(map_db)?,
                            encapsulation_key: row.try_get("encapsulation_key").map_err(map_db)?,
                            encapsulation: row.try_get("encapsulation").map_err(map_db)?,
                            prf_salt: row.try_get("prf_salt").map_err(map_db)?,
                            kdf_params: row.try_get("kdf_params").map_err(map_db)?,
                            wrap_nonce: row.try_get("wrap_nonce").map_err(map_db)?,
                            wrapped_key: row.try_get("wrapped_key").map_err(map_db)?,
                            revoked_at: revoked.map(u64_from).transpose()?,
                        })
                    })
                    .collect()
            }
        )
    }

    async fn revoke_recipient(
        &self,
        workspace_id: Uuid,
        id: Uuid,
        at: u64,
    ) -> Result<(), ApiError> {
        let stamped = i64::try_from(at).map_err(|_| ApiError::StoreUnavailable)?;
        on_pool!(
            self,
            "UPDATE recovery_recipients SET revoked_at = ? WHERE id = ? AND workspace_id = ?",
            |db, q| {
                let result = sqlx::query(q)
                    .bind(stamped)
                    .bind(id)
                    .bind(workspace_id)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                if result.rows_affected() == 0 {
                    Err(ApiError::NotFound)
                } else {
                    Ok(())
                }
            }
        )
    }

    async fn revoke_jti(
        &self,
        jti: Uuid,
        workspace_id: Uuid,
        expires_at: u64,
    ) -> Result<(), ApiError> {
        on_pool!(
            self,
            "INSERT INTO revoked_jtis (jti, workspace_id, expires_at) VALUES (?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(jti)
                    .bind(workspace_id)
                    .bind(i64_from(expires_at)?)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                Ok(())
            }
        )
    }

    async fn jti_is_revoked(&self, jti: Uuid, now: u64) -> Result<bool, ApiError> {
        on_pool!(
            self,
            "SELECT expires_at FROM revoked_jtis WHERE jti = ?",
            |db, q| {
                let row = sqlx::query(q)
                    .bind(jti)
                    .fetch_optional(db)
                    .await
                    .map_err(map_db)?;
                let Some(row) = row else {
                    return Ok(false);
                };
                let expires: i64 = row.try_get("expires_at").map_err(map_db)?;
                Ok(u64_from(expires)? > now)
            }
        )
    }

    async fn claim_dpop_jti(
        &self,
        jti: &str,
        workspace_id: Uuid,
        expires_at: u64,
    ) -> Result<(), ApiError> {
        let inserted = on_pool!(
            self,
            "INSERT INTO dpop_replay (jti, workspace_id, expires_at) VALUES (?, ?, ?)",
            |db, q| {
                match sqlx::query(q)
                    .bind(jti)
                    .bind(workspace_id)
                    .bind(i64_from(expires_at)?)
                    .execute(db)
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(err) => {
                        if let Some(db) = err.as_database_error() {
                            if db.is_unique_violation() {
                                Ok(false)
                            } else {
                                Err(map_db(err))
                            }
                        } else {
                            Err(map_db(err))
                        }
                    }
                }
            }
        )?;
        if inserted {
            Ok(())
        } else {
            Err(ApiError::Unauthenticated)
        }
    }

    async fn purge_dpop(&self, now: u64) -> Result<(), ApiError> {
        on_pool!(
            self,
            "DELETE FROM dpop_replay WHERE expires_at <= ?",
            |db, q| {
                sqlx::query(q)
                    .bind(i64_from(now)?)
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                Ok(())
            }
        )
    }

    async fn insert_rewrap_job(&self, job: RewrapJobRow) -> Result<(), ApiError> {
        on_pool!(
            self,
            "INSERT INTO rewrap_jobs (id, workspace_id, from_kek_id, to_kek_id, status, wrapped_count) VALUES (?, ?, ?, ?, ?, ?)",
            |db, q| {
                sqlx::query(q)
                    .bind(job.id)
                    .bind(job.workspace_id)
                    .bind(job.from_kek_id)
                    .bind(job.to_kek_id)
                    .bind(&job.status)
                    .bind(i64::try_from(job.wrapped_count).unwrap_or(i64::MAX))
                    .execute(db)
                    .await
                    .map_err(map_db)?;
                Ok(())
            }
        )
    }

    async fn finish_rewrap_job(
        &self,
        id: Uuid,
        status: &str,
        wrapped_count: u64,
    ) -> Result<(), ApiError> {
        let changed = on_pool!(
            self,
            "UPDATE rewrap_jobs SET status = ?, wrapped_count = ?, finished_at = ? WHERE id = ?",
            |db, q| {
                sqlx::query(q)
                    .bind(status)
                    .bind(i64::try_from(wrapped_count).unwrap_or(i64::MAX))
                    .bind(now_nanos())
                    .bind(id)
                    .execute(db)
                    .await
                    .map_err(map_db)?
                    .rows_affected()
            }
        );
        if changed == 0 {
            Err(ApiError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn pending_rewrap_jobs(&self) -> Result<Vec<RewrapJobRow>, ApiError> {
        on_pool!(
            self,
            "SELECT id, workspace_id, from_kek_id, to_kek_id, status, wrapped_count FROM rewrap_jobs WHERE status = 'pending'",
            |db, q| {
                let rows = sqlx::query(q).fetch_all(db).await.map_err(map_db)?;
                rows.iter()
                    .map(|row| {
                        let count: i64 = row.try_get("wrapped_count").map_err(map_db)?;
                        Ok(RewrapJobRow {
                            id: row.try_get("id").map_err(map_db)?,
                            workspace_id: row.try_get("workspace_id").map_err(map_db)?,
                            from_kek_id: row.try_get("from_kek_id").map_err(map_db)?,
                            to_kek_id: row.try_get("to_kek_id").map_err(map_db)?,
                            status: row.try_get("status").map_err(map_db)?,
                            wrapped_count: u64::try_from(count).unwrap_or(0),
                        })
                    })
                    .collect()
            }
        )
    }
}

const VERSION_COLS: &str = "SELECT id, secret_id, workspace_id, version, payload_alg, payload_nonce, payload_ciphertext, dek_wrap_alg, dek_wrap_nonce, dek_wrapped, kek_id, wrap_mode, e2e_encapsulation, plaintext_len FROM secret_versions";

const AUDIT_COLS: &str = "SELECT workspace_id, seq, agent_id, agent_seq, event_type, occurred_at, payload, prev_hash, hash, agent_prev_hash, agent_hash FROM audit_events";

async fn insert_kek_tx(tx: &mut SqlTx<'_>, kek: &KekRow, created: i64) -> Result<(), ApiError> {
    on_tx!(
        tx,
        "INSERT INTO kek_versions (id, workspace_id, version, status, wrapped_kek, kms_key_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        |db, q| {
            sqlx::query(q)
                .bind(kek.id)
                .bind(kek.workspace_id)
                .bind(i32::try_from(kek.version).map_err(|_| ApiError::StoreUnavailable)?)
                .bind(&kek.status)
                .bind(kek.wrapped_kek.as_slice())
                .bind(&kek.kms_key_ref)
                .bind(created)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        }
    );
    Ok(())
}

async fn insert_policy_tx(
    tx: &mut SqlTx<'_>,
    secret_id: Uuid,
    policy: &DeliveryPolicy,
) -> Result<(), ApiError> {
    let hosts = serde_json::to_string(&policy.hosts).map_err(|_| ApiError::StoreUnavailable)?;
    on_tx!(
        tx,
        "INSERT INTO secret_delivery_policies (secret_id, header_name, header_format, env_name, hosts, allow_proxy, allow_header, allow_env) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        |db, q| {
            sqlx::query(q)
                .bind(secret_id)
                .bind(&policy.header_name)
                .bind(&policy.header_format)
                .bind(&policy.env_name)
                .bind(&hosts)
                .bind(policy.allow_proxy)
                .bind(policy.allow_header)
                .bind(policy.allow_env)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        }
    );
    Ok(())
}

async fn insert_version_tx(
    tx: &mut SqlTx<'_>,
    version: &VersionRow,
    created: i64,
) -> Result<(), ApiError> {
    on_tx!(
        tx,
        "INSERT INTO secret_versions (id, secret_id, workspace_id, version, payload_alg, payload_nonce, payload_ciphertext, dek_wrap_alg, dek_wrap_nonce, dek_wrapped, kek_id, wrap_mode, e2e_encapsulation, plaintext_len, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        |db, q| {
            sqlx::query(q)
                .bind(version.id)
                .bind(version.secret_id)
                .bind(version.workspace_id)
                .bind(i32::try_from(version.version).map_err(|_| ApiError::StoreUnavailable)?)
                .bind(&version.sealed.payload_alg)
                .bind(version.sealed.payload_nonce.as_slice())
                .bind(version.sealed.payload_ciphertext.as_slice())
                .bind(&version.sealed.dek_wrap_alg)
                .bind(version.sealed.dek_wrap_nonce.as_slice())
                .bind(version.sealed.dek_wrapped.as_slice())
                .bind(version.kek_id)
                .bind(version.wrap_mode.as_str())
                .bind(version.e2e_encapsulation.as_deref())
                .bind(i32::try_from(version.sealed.plaintext_len).unwrap_or(i32::MAX))
                .bind(created)
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        }
    );
    Ok(())
}

async fn append_tx(tx: &mut SqlTx<'_>, draft: AuditDraft) -> Result<AuditRecord, ApiError> {
    let seq = on_tx!(
        tx,
        "UPDATE workspaces SET audit_seq = audit_seq + 1 WHERE id = ? RETURNING audit_seq",
        |db, q| {
            let seq_row = sqlx::query(q)
                .bind(draft.workspace_id)
                .fetch_optional(&mut **db)
                .await
                .map_err(map_db)?;
            let Some(seq_row) = seq_row else {
                return Err(ApiError::NotFound);
            };
            u64_from(seq_row.try_get("audit_seq").map_err(map_db)?)
        }
    )?;
    let prev = on_tx!(
        tx,
        "SELECT hash FROM audit_events WHERE workspace_id = ? ORDER BY seq DESC LIMIT 1",
        |db, q| {
            let prev_row = sqlx::query(q)
                .bind(draft.workspace_id)
                .fetch_optional(&mut **db)
                .await
                .map_err(map_db)?;
            match prev_row {
                Some(row) => arr32(row.try_get::<Vec<u8>, _>("hash").map_err(map_db)?),
                None => Ok([0u8; 32]),
            }
        }
    )?;
    let (agent_prev, agent_seq) = if let Some(agent) = draft.agent_id {
        on_tx!(
            tx,
            "SELECT agent_hash, agent_seq FROM audit_events WHERE workspace_id = ? AND agent_id = ? ORDER BY agent_seq DESC LIMIT 1",
            |db, q| {
                let tip = sqlx::query(q)
                    .bind(draft.workspace_id)
                    .bind(agent)
                    .fetch_optional(&mut **db)
                    .await
                    .map_err(map_db)?;
                match tip {
                    Some(row) => {
                        let hash = arr32(row.try_get::<Vec<u8>, _>("agent_hash").map_err(map_db)?)?;
                        let n = u64_from(row.try_get("agent_seq").map_err(map_db)?)?;
                        Ok((hash, n + 1))
                    }
                    None => Ok(([0u8; 32], 1)),
                }
            }
        )?
    } else {
        ([0u8; 32], 0)
    };
    let record = commit_event(draft, seq, prev, agent_prev, agent_seq);
    let payload = serde_json::to_string(&record.fields).map_err(|_| ApiError::StoreUnavailable)?;
    let agent_seq_db = if record.agent_id.is_some() {
        Some(i64_from(record.agent_seq)?)
    } else {
        None
    };
    on_tx!(
        tx,
        "INSERT INTO audit_events (workspace_id, seq, agent_id, agent_seq, event_type, occurred_at, payload, prev_hash, hash, agent_prev_hash, agent_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        |db, q| {
            sqlx::query(q)
                .bind(record.workspace_id)
                .bind(i64_from(record.seq)?)
                .bind(record.agent_id)
                .bind(agent_seq_db)
                .bind(&record.event_type)
                .bind(i64_from(record.occurred_at_nanos)?)
                .bind(&payload)
                .bind(record.prev_hash.as_slice())
                .bind(record.hash.as_slice())
                .bind(record.agent_id.map(|_| record.agent_prev_hash.as_slice()))
                .bind(record.agent_hash.as_ref().map(|hash| hash.as_slice()))
                .execute(&mut **db)
                .await
                .map_err(map_db)?;
        }
    );
    Ok(record)
}

// row mappers follow the pool macros so both engines type-check the same fields

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_require_and_verify_modes_enforce_tls() {
        let enforce = SqlStore::postgres_url_enforces_tls;
        assert!(enforce("postgres://u@db/app?sslmode=require"));
        assert!(enforce("postgresql://u@db/app?sslmode=verify-ca"));
        assert!(enforce(
            "postgres://u@db/app?application_name=g&sslmode=verify-full"
        ));
        assert!(!enforce("postgres://u@db/app"));
        assert!(!enforce("postgres://u@db/app?sslmode=prefer"));
        assert!(!enforce("postgres://u@db/app?sslmode=disable"));
        assert!(!enforce("postgres://u@db/app?sslmode=allow"));
        assert!(!enforce("postgres://u@db/app?sslmode=REQUIRE"));
        assert!(!enforce(
            "postgres://u@db/app?sslmode=require&sslmode=disable"
        ));
        assert!(!enforce("sqlite://dev.sqlite?sslmode=require"));
        assert!(!enforce("not a url"));
    }

    #[test]
    fn placeholders_are_numbered_for_postgres() {
        assert_eq!(
            pg_placeholders("SELECT a FROM t WHERE x = ? AND y = ?"),
            "SELECT a FROM t WHERE x = $1 AND y = $2"
        );
    }
}
