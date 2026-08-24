-- WebAuthn challenges are single-use server state. A response is valid only
-- against the exact state that created its challenge.
CREATE TABLE passkey_ceremony (
    id          UUID PRIMARY KEY,
    account_id  UUID REFERENCES account(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('register', 'authenticate')),
    state       JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX passkey_ceremony_expiry_idx ON passkey_ceremony (expires_at);
CREATE INDEX passkey_ceremony_account_idx ON passkey_ceremony (account_id);
