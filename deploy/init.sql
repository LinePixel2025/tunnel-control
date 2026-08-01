CREATE TABLE IF NOT EXISTS workspaces (id UUID PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces(id), email TEXT NOT NULL UNIQUE, role TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS access_tokens (id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces(id), label TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS devices (id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces(id), name TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS tunnels (id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces(id), device_id UUID REFERENCES devices(id), name TEXT NOT NULL, kind TEXT NOT NULL, public_port INTEGER NOT NULL UNIQUE, local_host TEXT NOT NULL, local_port INTEGER NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true, max_connections INTEGER NOT NULL DEFAULT 100);
CREATE TABLE IF NOT EXISTS audit_events (id UUID PRIMARY KEY, workspace_id UUID REFERENCES workspaces(id), actor_id UUID REFERENCES users(id), action TEXT NOT NULL, subject TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());

