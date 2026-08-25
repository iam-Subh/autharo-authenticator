-- 0009: verified WebAuthn credentials. Ceremony state remains in the table
-- created by 0005 and is deleted before each response is accepted.

CREATE TABLE passkey_credential (
    id            UUID PRIMARY KEY,
    account_id    UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    user_handle   BYTEA NOT NULL,
    public_key    JSONB NOT NULL,
    credential    JSONB NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports    TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    prf_salt      BYTEA NOT NULL,
    prf_supported BOOLEAN NOT NULL,
    wrapped_key   BYTEA,
    wrap_nonce    BYTEA,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used     TIMESTAMPTZ,
    CHECK (
        (prf_supported AND wrapped_key IS NOT NULL AND wrap_nonce IS NOT NULL)
        OR (NOT prf_supported AND wrapped_key IS NULL AND wrap_nonce IS NULL)
    )
);

CREATE INDEX passkey_credential_account_idx
    ON passkey_credential (account_id, created_at);
