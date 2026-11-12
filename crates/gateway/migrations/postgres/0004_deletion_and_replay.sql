-- Workspace deletion keeps its deadline in the store, so a gateway that holds
-- no root key can still finish or cancel a deletion. delete_after is unix
-- seconds. A row already in 'deleting' gets a fresh seven-day window.
--
-- DPoP replay rows are keyed per workspace. One tenant's jti no longer blocks
-- or collides with another tenant's proof.

ALTER TABLE workspaces ADD COLUMN delete_after bigint;

UPDATE workspaces
   SET delete_after = CAST(EXTRACT(EPOCH FROM now()) AS bigint) + 604800
 WHERE status = 'deleting' AND delete_after IS NULL;

ALTER TABLE dpop_replay DROP CONSTRAINT dpop_replay_pkey;
ALTER TABLE dpop_replay ADD PRIMARY KEY (workspace_id, jti);
