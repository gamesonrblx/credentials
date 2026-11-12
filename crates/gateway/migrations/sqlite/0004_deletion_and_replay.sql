-- Workspace deletion keeps its deadline in the store, so a gateway that holds
-- no root key can still finish or cancel a deletion. delete_after is unix
-- seconds. A row already in 'deleting' gets a fresh seven-day window.
--
-- DPoP replay rows are keyed per workspace. One tenant's jti no longer blocks
-- or collides with another tenant's proof.

ALTER TABLE workspaces ADD COLUMN delete_after integer;

UPDATE workspaces
   SET delete_after = CAST(strftime('%s', 'now') AS integer) + 604800
 WHERE status = 'deleting' AND delete_after IS NULL;

CREATE TABLE dpop_replay_v2 (
    workspace_id text NOT NULL,
    jti          text NOT NULL,
    expires_at   integer NOT NULL,
    PRIMARY KEY (workspace_id, jti)
);

INSERT INTO dpop_replay_v2 (workspace_id, jti, expires_at)
    SELECT workspace_id, jti, expires_at FROM dpop_replay;

DROP INDEX dpop_replay_expiry;
DROP TABLE dpop_replay;
ALTER TABLE dpop_replay_v2 RENAME TO dpop_replay;

CREATE INDEX dpop_replay_expiry ON dpop_replay (expires_at);
