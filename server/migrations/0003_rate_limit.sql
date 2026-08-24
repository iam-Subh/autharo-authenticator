-- Section 9.5: "Rate-limit sign-in to 10 attempts per account per hour and 100
-- per IP address per hour."
--
-- In PostgreSQL rather than Redis, which section 14.2 names. Redis is the right
-- answer at scale and this is not that yet: sign-in is rare, already costs an
-- Argon2id hash, and one more indexed query against a table that stays small is
-- lost in the noise. Moving it later changes this file and `ratelimit.rs` and
-- nothing else.
--
-- What is deliberately *not* stored: whether the attempt succeeded, and whether
-- the address belongs to an account. Both would make this table an enumeration
-- oracle for anyone who reached the database, which is the attacker section 9.1
-- puts first.
CREATE TABLE auth_attempt (
    id      BIGSERIAL PRIMARY KEY,
    -- The normalised email address, or the client address. Held as text so one
    -- table serves both, and counted separately by `kind`.
    subject TEXT        NOT NULL,
    kind    TEXT        NOT NULL CHECK (kind IN ('account', 'address')),
    at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The only query this table serves: how many attempts of one kind for one
-- subject since a moment. Ordered so the count is an index-only scan.
CREATE INDEX auth_attempt_window_idx ON auth_attempt (kind, subject, at DESC);

-- For the sweep that discards rows past the window.
CREATE INDEX auth_attempt_age_idx ON auth_attempt (at);
