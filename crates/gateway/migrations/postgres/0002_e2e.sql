-- Customer workspace encapsulation keys and recovery wraps.
-- The decapsulation key is not a column. kind has no operator value.

CREATE TABLE workspace_keys (
    id                 uuid PRIMARY KEY,
    workspace_id       uuid NOT NULL REFERENCES workspaces (id),
    encapsulation_key  bytea NOT NULL,
    created_at         bigint NOT NULL,
    UNIQUE (workspace_id)
);

CREATE TABLE recovery_recipients (
    id                 uuid PRIMARY KEY,
    workspace_id       uuid NOT NULL REFERENCES workspaces (id),
    kind               text NOT NULL CHECK (kind IN ('device', 'passkey', 'recovery_kit', 'teammate')),
    encapsulation_key  bytea,
    encapsulation      bytea,
    prf_salt           bytea,
    kdf_params         text,
    wrap_nonce         bytea NOT NULL,
    wrapped_key        bytea NOT NULL,
    created_at         bigint NOT NULL,
    revoked_at         bigint
);
