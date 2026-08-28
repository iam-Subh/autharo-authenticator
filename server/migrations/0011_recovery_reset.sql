-- One-time recovery ceremonies for forgotten-password reset.
-- The token is random and stored only as a SHA-256 digest.

CREATE TABLE recovery_reset (
    id         UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX recovery_reset_account_idx
    ON recovery_reset (account_id, expires_at DESC);
CREATE INDEX recovery_reset_expiry_idx
    ON recovery_reset (expires_at);
