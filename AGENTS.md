# Repository Guidelines

## Project Structure & Module Organization

- `crates/protocol`: versioned control protocol, frame encoding, and unit tests.
- `crates/server`: Axum management API, WebSocket control channel, and TCP/HTTP forwarding.
- `crates/agent`: Windows agent; supports console mode (`--agent`) and a real Windows service (`--service`).
- `apps/admin`: React admin console served by Nginx.
- `apps/client`: Tauri + React Windows GUI.
- `deploy/`: Docker Compose files, Dockerfiles, Nginx config, SQL migrations, and Windows installers.

Database migrations live in `deploy/migrations/`; do not duplicate schema definitions elsewhere.

## Build, Test, and Development Commands

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo build --release -p tunnel-server
cargo build --release -p tunnel-agent
```

Frontend builds:

```bash
cd apps/admin && npm install && npm run build
cd apps/client && npm install && npm run build
cd apps/client && npm run tauri -- build --no-bundle
```

Server deployment:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
```

1Panel uses `deploy/compose.1panel.yaml` with a prebuilt server binary in `deploy/bin/`.

## Coding Style & Naming Conventions

- Rust: run `cargo fmt`; use `snake_case`, concise comments, and ASCII source text.
- TypeScript/React: two-space indentation, `camelCase` for variables, and existing JSX formatting.
- Keep comments for non-obvious logic only; avoid restating code.
- Never commit generated output such as `target/`, `node_modules/`, `build/`, or `release/`.

## Testing Guidelines

- Protocol tests live in `crates/protocol/src/lib.rs`; run with `cargo test --workspace`.
- TypeScript is checked with `tsc --noEmit` during `npm run build`.
- Before merging changes to the data plane, verify an end-to-end TCP/HTTP tunnel against a running Compose stack.

## Commit & Pull Request Guidelines

- Use short, imperative commit messages based on repository history, for example `Fix GUI save_config argument names` or `Add one-click service installer`.
- Scope each commit to one logical change.
- Pull requests should describe the user-visible behavior, deployment impact, and verification steps.
- Include screenshots for GUI changes and paste key test output for protocol or service changes.
- Flag security-relevant changes such as credential handling, port exposure, or TLS decisions.

## Security & Configuration Tips

- Copy `deploy/.env.example` to `deploy/.env` and generate strong secrets; never commit `.env` or real tokens.
- The current deployment uses HTTP/WS without TLS; restrict management and tunnel ports to trusted sources.
- Rotate `POSTGRES_PASSWORD`, `JWT_SECRET`, admin credentials, and device tokens before production use.
