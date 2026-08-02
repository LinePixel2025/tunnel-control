-- Admin-created access keys: a key stays unbound until the first agent connects.
ALTER TABLE access_tokens ALTER COLUMN device_id DROP NOT NULL;
ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
