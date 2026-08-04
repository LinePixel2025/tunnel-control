# Repository Guidelines

## Project Structure & Module Organization

- `crates/protocol`: versioned control protocol, frame encoding, and unit tests.
- `crates/server`: Axum management API, WebSocket control channel, and TCP/HTTP forwarding.
- `crates/agent`: Windows agent; supports console mode (`--agent`), a real Windows service (`--service`), device-code enrollment, and the `logs` CLI.
- `apps/admin`: React admin console served by Nginx.
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
```

Server deployment:

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
```

1Panel uses `deploy/compose.1panel.yaml` with a prebuilt server binary in `deploy/bin/`.

## Client Packaging

Every client release is versioned and stored in its own folder under
`release/V<version>/`; the `release/` directory is gitignored.

Release steps:

1. Bump the version:
   - `version` in `Cargo.toml` (workspace package), which also updates
     `Cargo.lock` on the next build.
   - The release line and installer path in `README.md`.
   - `TargetName` / `FriendlyName` in `deploy/windows/iexpress.sed` (legacy
     IExpress descriptor kept in sync even though packaging uses the native
     installer script below).
2. Build and package:

```powershell
cargo build --release -p tunnel-agent
.\deploy\windows\build-installer.ps1 -Version 4.2
```

`build-installer.ps1` with `-Version` writes two identical copies of the
release binary into `release\V4.2\`:

- `tunnel-agent.exe` — the native CLI installer / client executable.
- `Tunnel-Agent-Setup-V4.2.exe` — the same binary under the documented setup
  package name.

3. Distribute `release\V4.2\Tunnel-Agent-Setup-V4.2.exe` to target Windows
   machines. Install with:

```powershell
.\tunnel-agent.exe --install --server ws://SERVER_IP:18080/control
```

4. Verify the release: `Get-Service TunnelAgent` is running, the agent
   enrolls/connects in the admin console, and a tunnel passes traffic.

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

- Use short, imperative commit messages based on repository history, for example `Add device-code enrollment` or `Push agent settings from admin`.
- Scope each commit to one logical change.
- Pull requests should describe the user-visible behavior, deployment impact, and verification steps.
- Include screenshots for admin console changes and paste key test output for protocol or service changes.
- Flag security-relevant changes such as credential handling, port exposure, or TLS decisions.

## Security & Configuration Tips

- Copy `deploy/.env.example` to `deploy/.env` and generate strong secrets; never commit `.env` or real tokens.
- The current deployment uses HTTP/WS without TLS; restrict management and tunnel ports to trusted sources.
- Rotate `POSTGRES_PASSWORD`, `JWT_SECRET`, admin credentials, and device tokens before production use.
