-- Detect reuse of a rotated refresh token and revoke all of its descendants.

ALTER TABLE session ADD COLUMN family_id UUID;
UPDATE session SET family_id = id;
ALTER TABLE session ALTER COLUMN family_id SET NOT NULL;

CREATE INDEX session_family_idx ON session (family_id);
CREATE UNIQUE INDEX session_refresh_all_idx ON session (refresh_hash);
