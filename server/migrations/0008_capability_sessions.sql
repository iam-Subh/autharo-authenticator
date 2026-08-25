-- 0008: persistent sessions keep only background permissions. Interactive
-- security and sharing actions use short-lived, non-refreshable capabilities.

UPDATE session
   SET scopes = ARRAY['vault:sync', 'session:self']::TEXT[];

ALTER TABLE session
    ALTER COLUMN scopes SET DEFAULT ARRAY[
        'vault:sync',
        'session:self'
    ]::TEXT[];

CREATE TABLE capability_session (
    id                UUID PRIMARY KEY,
    parent_session_id UUID NOT NULL REFERENCES session(id) ON DELETE CASCADE,
    token_hash        BYTEA NOT NULL UNIQUE,
    scopes            TEXT[] NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    revoked           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (cardinality(scopes) > 0),
    CHECK (scopes <@ ARRAY['security:read', 'share:write']::TEXT[])
);

CREATE INDEX capability_session_parent_idx
    ON capability_session (parent_session_id, expires_at DESC);

CREATE INDEX capability_session_expiry_idx
    ON capability_session (expires_at);
