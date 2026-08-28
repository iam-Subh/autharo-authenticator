CREATE TABLE account_identity (
    account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    subject TEXT PRIMARY KEY,
    verified_email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id)
);

CREATE INDEX account_identity_account_idx ON account_identity (account_id);
