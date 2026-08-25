-- 0010: an FCM registration token routes a generic vault-change signal to one
-- device. It is not an account credential and it never appears in API output.
ALTER TABLE device
    ADD COLUMN push_token_updated_at TIMESTAMPTZ,
    ADD COLUMN push_failures INTEGER NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX device_push_token_unique_idx
    ON device (push_token)
    WHERE push_token IS NOT NULL;
