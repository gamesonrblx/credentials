-- Logical schema from docs/ENCRYPTION.md section 7.
-- Instants are unix nanoseconds (bigint), not timestamptz, so SQLite and
-- Postgres share one mapping. Bytes are bytea. JSON metadata is text.
-- wrap_mode accepts 'e2e' so M3 does not rewrite gateway rows. Writers
-- reject that value until the mode exists.

CREATE TABLE workspaces (
    id                   uuid PRIMARY KEY,
    status               text NOT NULL CHECK (status IN ('active', 'deleting', 'shredded')),
    kms_key_ref          text NOT NULL,
    audit_seq            bigint NOT NULL DEFAULT 0,
    audit_retention_days integer NOT NULL DEFAULT 90,
    created_at           bigint NOT NULL,
    deleting_at          bigint,
    shredded_at          bigint
);

CREATE TABLE kek_versions (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id),
    version       integer NOT NULL CHECK (version >= 1),
    status        text NOT NULL CHECK (status IN ('active', 'decrypt_only', 'retired', 'destroyed')),
    wrapped_kek   bytea,
    kms_key_ref   text NOT NULL,
    created_at    bigint NOT NULL,
    UNIQUE (workspace_id, version)
);

CREATE UNIQUE INDEX kek_one_active
    ON kek_versions (workspace_id)
    WHERE status = 'active';

CREATE TABLE secrets (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL REFERENCES workspaces (id),
    name          text NOT NULL,
    status        text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at    bigint NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE secret_delivery_policies (
    secret_id     uuid PRIMARY KEY REFERENCES secrets (id),
    header_name   text,
    header_format text,
    env_name      text,
    hosts         text NOT NULL,
    allow_proxy   boolean NOT NULL,
    allow_header  boolean NOT NULL,
    allow_env     boolean NOT NULL
);

CREATE TABLE secret_versions (
    id                  uuid PRIMARY KEY,
    secret_id           uuid NOT NULL REFERENCES secrets (id),
    workspace_id        uuid NOT NULL,
    version             integer NOT NULL CHECK (version >= 1),
    payload_alg         text NOT NULL,
    payload_nonce       bytea NOT NULL,
    payload_ciphertext  bytea NOT NULL,
    dek_wrap_alg        text NOT NULL,
    dek_wrap_nonce      bytea NOT NULL,
    dek_wrapped         bytea NOT NULL,
    kek_id              uuid NOT NULL REFERENCES kek_versions (id),
    wrap_mode           text NOT NULL CHECK (wrap_mode IN ('gateway', 'e2e')),
    e2e_encapsulation   bytea,
    plaintext_len       integer NOT NULL,
    created_at          bigint NOT NULL,
    UNIQUE (secret_id, version)
);

CREATE INDEX secret_versions_by_kek ON secret_versions (kek_id);

CREATE TABLE rewrap_jobs (
    id            uuid PRIMARY KEY,
    workspace_id  uuid NOT NULL,
    from_kek_id   uuid NOT NULL,
    to_kek_id     uuid NOT NULL,
    status        text NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
    cursor_id     uuid,
    wrapped_count bigint NOT NULL DEFAULT 0,
    error         text,
    started_at    bigint,
    finished_at   bigint
);

CREATE TABLE audit_events (
    workspace_id    uuid NOT NULL,
    seq             bigint NOT NULL,
    agent_id        uuid,
    agent_seq       bigint,
    event_type      text NOT NULL,
    occurred_at     bigint NOT NULL,
    payload         text NOT NULL,
    prev_hash       bytea NOT NULL,
    hash            bytea NOT NULL,
    agent_prev_hash bytea,
    agent_hash      bytea,
    PRIMARY KEY (workspace_id, seq)
);

CREATE INDEX audit_events_by_agent
    ON audit_events (workspace_id, agent_id, agent_seq);

CREATE TABLE audit_checkpoints (
    workspace_id uuid NOT NULL,
    seq          bigint NOT NULL,
    tip_hash     bytea NOT NULL,
    kid          text NOT NULL,
    signature    bytea NOT NULL,
    anchored_at  bigint,
    PRIMARY KEY (workspace_id, seq)
);

CREATE TABLE signing_keys (
    kid          text PRIMARY KEY,
    purpose      text NOT NULL CHECK (purpose IN ('token', 'audit')),
    alg          text NOT NULL CHECK (alg IN ('EdDSA', 'ES256')),
    public_key   bytea NOT NULL,
    status       text NOT NULL CHECK (status IN ('active', 'verify_only', 'retired')),
    kms_key_ref  text NOT NULL,
    created_at   bigint NOT NULL
);

CREATE TABLE workspace_credentials (
    id           uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    secret_hash  bytea NOT NULL UNIQUE,
    created_at   bigint NOT NULL,
    revoked_at   bigint
);

CREATE TABLE agents (
    id           uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES workspaces (id),
    display_name text NOT NULL,
    status       text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at   bigint NOT NULL
);

CREATE TABLE agent_sessions (
    id           uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    agent_id     uuid NOT NULL REFERENCES agents (id),
    dpop_jkt     text NOT NULL,
    scopes       text NOT NULL,
    expires_at   bigint NOT NULL,
    revoked_at   bigint
);

CREATE TABLE revoked_jtis (
    jti          uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    expires_at   bigint NOT NULL
);
