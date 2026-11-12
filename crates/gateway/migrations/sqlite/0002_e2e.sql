-- Customer workspace encapsulation keys and recovery wraps.
-- The decapsulation key is not a column. kind has no operator value.

CREATE TABLE workspace_keys (
    id                 text PRIMARY KEY,
    workspace_id       text NOT NULL REFERENCES workspaces (id),
    encapsulation_key  blob NOT NULL,
    created_at         integer NOT NULL,
    UNIQUE (workspace_id)
);

CREATE TABLE recovery_recipients (
    id                 text PRIMARY KEY,
    workspace_id       text NOT NULL REFERENCES workspaces (id),
    kind               text NOT NULL CHECK (kind IN ('device', 'passkey', 'recovery_kit', 'teammate')),
    encapsulation_key  blob,
    encapsulation      blob,
    prf_salt           blob,
    kdf_params         text,
    wrap_nonce         blob NOT NULL,
    wrapped_key        blob NOT NULL,
    created_at         integer NOT NULL,
    revoked_at         integer
);
