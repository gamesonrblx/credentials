-- Token revocation and DPoP replay survive a process restart.
-- DPoP jti values are strings, so they do not use the uuid column.

ALTER TABLE agent_sessions ADD COLUMN token_jti uuid;

CREATE TABLE dpop_replay (
    jti          text PRIMARY KEY,
    workspace_id uuid NOT NULL,
    expires_at   bigint NOT NULL
);

CREATE INDEX dpop_replay_expiry ON dpop_replay (expires_at);
