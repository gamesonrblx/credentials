-- SQLite rendering of the logical schema. Uniqueness, byte columns, and
-- transactions match the Postgres migration. UUIDs are canonical text.
-- Instants are unix nanoseconds. hosts, scopes, and audit payloads are JSON
-- text. Bytes are blobs, never base64.

CREATE TABLE workspaces (
    id                   text PRIMARY KEY,
    status               text NOT NULL CHECK (status IN ('active', 'deleting', 'shredded')),
    kms_key_ref          text NOT NULL,
    audit_seq            integer NOT NULL DEFAULT 0,
    audit_retention_days integer NOT NULL DEFAULT 90,
    created_at           integer NOT NULL,
    deleting_at          integer,
    shredded_at          integer
);

CREATE TABLE kek_versions (
    id            text PRIMARY KEY,
    workspace_id  text NOT NULL REFERENCES workspaces (id),
    version       integer NOT NULL CHECK (version >= 1),
    status        text NOT NULL CHECK (status IN ('active', 'decrypt_only', 'retired', 'destroyed')),
    wrapped_kek   blob,
    kms_key_ref   text NOT NULL,
    created_at    integer NOT NULL,
    UNIQUE (workspace_id, version)
);

CREATE UNIQUE INDEX kek_one_active
    ON kek_versions (workspace_id)
    WHERE status = 'active';

CREATE TABLE secrets (
    id            text PRIMARY KEY,
    workspace_id  text NOT NULL REFERENCES workspaces (id),
    name          text NOT NULL,
    status        text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at    integer NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE secret_delivery_policies (
    secret_id     text PRIMARY KEY REFERENCES secrets (id),
    header_name   text,
    header_format text,
    env_name      text,
    hosts         text NOT NULL,
    allow_proxy   integer NOT NULL,
    allow_header  integer NOT NULL,
    allow_env     integer NOT NULL
);

CREATE TABLE secret_versions (
    id                  text PRIMARY KEY,
    secret_id           text NOT NULL REFERENCES secrets (id),
    workspace_id        text NOT NULL,
    version             integer NOT NULL CHECK (version >= 1),
    payload_alg         text NOT NULL,
    payload_nonce       blob NOT NULL,
    payload_ciphertext  blob NOT NULL,
    dek_wrap_alg        text NOT NULL,
    dek_wrap_nonce      blob NOT NULL,
    dek_wrapped         blob NOT NULL,
    kek_id              text NOT NULL REFERENCES kek_versions (id),
    wrap_mode           text NOT NULL CHECK (wrap_mode IN ('gateway', 'e2e')),
    e2e_encapsulation   blob,
    plaintext_len       integer NOT NULL,
    created_at          integer NOT NULL,
    UNIQUE (secret_id, version)
);

CREATE INDEX secret_versions_by_kek ON secret_versions (kek_id);

CREATE TABLE rewrap_jobs (
    id            text PRIMARY KEY,
    workspace_id  text NOT NULL,
    from_kek_id   text NOT NULL,
    to_kek_id     text NOT NULL,
    status        text NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
    cursor_id     text,
    wrapped_count integer NOT NULL DEFAULT 0,
    error         text,
    started_at    integer,
    finished_at   integer
);

CREATE TABLE audit_events (
    workspace_id    text NOT NULL,
    seq             integer NOT NULL,
    agent_id        text,
    agent_seq       integer,
    event_type      text NOT NULL,
    occurred_at     integer NOT NULL,
    payload         text NOT NULL,
    prev_hash       blob NOT NULL,
    hash            blob NOT NULL,
    agent_prev_hash blob,
    agent_hash      blob,
    PRIMARY KEY (workspace_id, seq)
);

CREATE INDEX audit_events_by_agent
    ON audit_events (workspace_id, agent_id, agent_seq);

CREATE TABLE audit_checkpoints (
    workspace_id text NOT NULL,
    seq          integer NOT NULL,
    tip_hash     blob NOT NULL,
    kid          text NOT NULL,
    signature    blob NOT NULL,
    anchored_at  integer,
    PRIMARY KEY (workspace_id, seq)
);

CREATE TABLE signing_keys (
    kid          text PRIMARY KEY,
    purpose      text NOT NULL CHECK (purpose IN ('token', 'audit')),
    alg          text NOT NULL CHECK (alg IN ('EdDSA', 'ES256')),
    public_key   blob NOT NULL,
    status       text NOT NULL CHECK (status IN ('active', 'verify_only', 'retired')),
    kms_key_ref  text NOT NULL,
    created_at   integer NOT NULL
);

CREATE TABLE workspace_credentials (
    id           text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces (id),
    secret_hash  blob NOT NULL UNIQUE,
    created_at   integer NOT NULL,
    revoked_at   integer
);

CREATE TABLE agents (
    id           text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces (id),
    display_name text NOT NULL,
    status       text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at   integer NOT NULL
);

CREATE TABLE agent_sessions (
    id           text PRIMARY KEY,
    workspace_id text NOT NULL,
    agent_id     text NOT NULL REFERENCES agents (id),
    dpop_jkt     text NOT NULL,
    scopes       text NOT NULL,
    expires_at   integer NOT NULL,
    revoked_at   integer
);

CREATE TABLE revoked_jtis (
    jti          text PRIMARY KEY,
    workspace_id text NOT NULL,
    expires_at   integer NOT NULL
);
