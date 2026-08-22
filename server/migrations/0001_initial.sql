-- 0001: the initial schema (PRD section 12.3).
--
-- Versioned from the first migration on purpose. Stage S7 adds passkey slots
-- and will alter `key_slot`; a schema created by hand now would leave no way
-- to apply that change to a deployed database.
--
-- What this schema is designed NOT to hold: an issuer, an account name, or a
-- secret. Those live inside `record.ciphertext`, which the server cannot
-- decrypt. The S4 exit criterion is a dump of this database containing none of
-- them, and `tests/dump.rs` asserts it.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE account (
    id          UUID PRIMARY KEY,
    -- Required for every synced account, including a passkey account
    -- (decision 6, section 16.4). Recovery, device approval, and support all
    -- key on it. CITEXT so that a differently-cased address is the same
    -- account rather than a second one.
    email       CITEXT UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE key_slot (
    id           UUID PRIMARY KEY,
    account_id   UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    type         TEXT NOT NULL CHECK (type IN ('password', 'passkey', 'recovery')),
    label        TEXT,

    -- The vault key wrapped by this slot's KEK. Ciphertext the server cannot
    -- open: the KEK never leaves the client (section 9.2).
    wrapped_key  BYTEA NOT NULL,
    wrap_nonce   BYTEA NOT NULL,

    -- Password slots only. `kdf_params` and the client salt are public and are
    -- returned by prelogin so a client can reproduce its derivation.
    kdf_params   JSONB,
    client_salt  BYTEA,

    -- Password slots only, and the important one: this is Argon2id OVER the
    -- authentication key, with a server-side salt (section 9.2.1 step 5). The
    -- authentication key itself is never stored. A dump of this column does
    -- not let an attacker sign in.
    auth_hash    TEXT,

    -- Passkey slots only. Unused until S7; the columns exist so that stage
    -- adds rows rather than altering a live table.
    cred_id      BYTEA,
    cred_pubkey  BYTEA,
    sign_count   BIGINT,
    prf_salt     BYTEA,

    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used    TIMESTAMPTZ
);

CREATE UNIQUE INDEX key_slot_cred_idx
    ON key_slot (cred_id) WHERE cred_id IS NOT NULL;

-- Section 9.2: "A synced account must always hold exactly one recovery slot."
CREATE UNIQUE INDEX key_slot_one_recovery_idx
    ON key_slot (account_id) WHERE type = 'recovery';

-- And at most one password slot (section 9.2's table: 0 or 1).
CREATE UNIQUE INDEX key_slot_one_password_idx
    ON key_slot (account_id) WHERE type = 'password';

CREATE INDEX key_slot_account_idx ON key_slot (account_id);

CREATE TABLE record (
    account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    entry_id    UUID NOT NULL,
    -- NULL for a tombstone. Never readable by the server.
    ciphertext  BYTEA,
    nonce       BYTEA,
    hlc         TEXT NOT NULL,
    deleted     BOOLEAN NOT NULL DEFAULT FALSE,
    seq         BIGSERIAL,
    PRIMARY KEY (account_id, entry_id)
);

CREATE INDEX record_sync_idx ON record (account_id, seq);

CREATE TABLE sync_state (
    account_id       UUID PRIMARY KEY REFERENCES account(id) ON DELETE CASCADE,
    prune_watermark  BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE device (
    id           UUID PRIMARY KEY,
    account_id   UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    push_token   TEXT,
    last_seen    TIMESTAMPTZ,
    revoked      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX device_account_idx ON device (account_id);
