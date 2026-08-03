-- Device-code enrollment: an agent connects without a token, shows a
-- one-time 8-character code, and waits for an admin to approve it. The code
-- is stored only as a SHA-256 hash and expires after ENROLL_TTL_MINUTES.
CREATE TABLE IF NOT EXISTS enrollments (
    id UUID PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    device_id UUID REFERENCES devices(id)
);

-- Per-device overrides over the global agent defaults in `settings`. NULL
-- means "inherit the global default"; the server merges the two when pushing
-- SettingsSync to an online agent.
CREATE TABLE IF NOT EXISTS device_settings (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    server_url TEXT,
    data_channels SMALLINT,
    heartbeat_secs INTEGER,
    pong_timeout_secs INTEGER,
    reconnect_min_secs INTEGER,
    reconnect_max_secs INTEGER,
    log_level TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Global agent defaults live in the settings key/value table. They are
-- inserted lazily on first write; keys:
--   agent.server_url, agent.data_channels, agent.heartbeat_secs,
--   agent.pong_timeout_secs, agent.reconnect_min_secs,
--   agent.reconnect_max_secs, agent.log_level
