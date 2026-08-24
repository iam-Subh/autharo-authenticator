-- Temporary shares contain only client-encrypted data. The decryption key is
-- in the URL fragment and never reaches this table.
CREATE TABLE temporary_share (
    id          UUID PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    payload     BYTEA NOT NULL,
    one_time    BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX temporary_share_expiry_idx ON temporary_share (expires_at);
CREATE INDEX temporary_share_account_idx ON temporary_share (account_id);
