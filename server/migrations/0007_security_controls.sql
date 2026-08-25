-- 0007: scoped sessions, approved devices, and account security events.

ALTER TABLE session
    ADD COLUMN scopes TEXT[] NOT NULL DEFAULT ARRAY[
        'vault:sync',
        'security:read',
        'share:write',
        'session:self'
    ]::TEXT[];

CREATE TABLE device_approval (
    id                   UUID PRIMARY KEY,
    account_id           UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    created_by_device_id UUID REFERENCES device(id) ON DELETE SET NULL,
    token_hash           BYTEA NOT NULL UNIQUE,
    expires_at           TIMESTAMPTZ NOT NULL,
    used_at              TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX device_approval_account_idx
    ON device_approval (account_id, expires_at DESC);

CREATE TABLE security_event (
    id         BIGSERIAL PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    device_id  UUID REFERENCES device(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    detail     JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX security_event_account_time_idx
    ON security_event (account_id, created_at DESC, id DESC);
