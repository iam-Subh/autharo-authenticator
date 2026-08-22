-- 0002: sessions.
--
-- A separate migration rather than an edit to 0001, and that is the point:
-- 0001 is already the shape a deployed database would have, so every later
-- change has to be applied as its own step. Stage S7 alters `key_slot` for
-- passkeys and will do the same.
--
-- Section 13 sets the lifetimes: an access token lasts 15 minutes and a
-- refresh token 30 days. Both are stored hashed rather than in the clear, for
-- the same reason as `auth_hash`: a dump of this table must not let anyone
-- resume a session.

CREATE TABLE session (
    id                 UUID PRIMARY KEY,
    account_id         UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    device_id          UUID REFERENCES device(id) ON DELETE SET NULL,

    -- SHA-256 of the token. Not Argon2id: a token is 256 random bits, so
    -- there is nothing to brute force and no reason to pay the cost on every
    -- authenticated request.
    access_hash        BYTEA NOT NULL,
    refresh_hash       BYTEA NOT NULL,

    access_expires_at  TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked            BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX session_access_idx ON session (access_hash) WHERE NOT revoked;
CREATE INDEX session_refresh_idx ON session (refresh_hash) WHERE NOT revoked;
CREATE INDEX session_account_idx ON session (account_id);
