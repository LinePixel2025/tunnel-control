#!/usr/bin/env bash
#
# Remote deploy script for Tunnel Control. Runs on the Linux server inside
# the deployment directory (1Panel: /opt/1panel/docker/compose/tunnel-control).
#
# Safe by design:
#   - Never runs `docker compose down -v` or removes volumes: the named
#     external volumes postgres-data / redis-data survive every redeploy.
#   - Optionally takes a PostgreSQL dump before touching the stack.
#   - Only uses `up -d --build`, which recreates changed containers without
#     deleting data.
#   - Never deletes server-only files (CI rsync has no --delete).
#
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/tunnel-control}"
DEPLOY_SUBDIR="${DEPLOY_SUBDIR:-}"
ENV_FILE="${ENV_FILE:-1panel.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose.1panel.yaml}"
PROJECT_NAME="${PROJECT_NAME:-tunnel-control}"
BACKUP_ENABLED="${BACKUP_ENABLED:-1}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"

APP_DIR="$DEPLOY_DIR${DEPLOY_SUBDIR:+/$DEPLOY_SUBDIR}"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/deploy/backups}"

# ENV_FILE is resolved against DEPLOY_DIR (1Panel keeps 1panel.env next to source/).
case "$ENV_FILE" in
  /*) ENV_PATH="$ENV_FILE" ;;
  *)  ENV_PATH="$DEPLOY_DIR/$ENV_FILE" ;;
esac

# COMPOSE_FILE is repo-relative. Copy it next to the deployment directory so the
# `./source` build context in the file resolves correctly, without touching the
# compose file that 1Panel manages.
case "$COMPOSE_FILE" in
  /*) SRC_COMPOSE="$COMPOSE_FILE" ;;
  *)  SRC_COMPOSE="$APP_DIR/$COMPOSE_FILE" ;;
esac
COMPOSE_PATH="$DEPLOY_DIR/docker-compose.ci.yml"

for f in "$ENV_PATH" "$SRC_COMPOSE"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required file missing: $f" >&2
    exit 1
  fi
done

cp "$SRC_COMPOSE" "$COMPOSE_PATH"
cd "$DEPLOY_DIR"

COMPOSE=(docker compose -p "$PROJECT_NAME" --env-file "$ENV_PATH" -f "$COMPOSE_PATH")

echo "Validating compose configuration..."
"${COMPOSE[@]}" config -q

# 1. Optional database backup before touching the stack.
if [[ "$BACKUP_ENABLED" == "1" ]] && "${COMPOSE[@]}" ps --status running --quiet postgres | grep -q .; then
  mkdir -p "$BACKUP_DIR"
  stamp=$(date +%Y%m%d-%H%M%S)
  out="$BACKUP_DIR/tunnel-$stamp.sql.gz"
  echo "Backing up PostgreSQL to $out ..."
  "${COMPOSE[@]}" exec -T postgres pg_dump -U tunnel tunnel | gzip > "$out"
  find "$BACKUP_DIR" -name 'tunnel-*.sql.gz' -mtime "+$BACKUP_KEEP_DAYS" -delete
  echo "Backup finished: $out"
fi

# 2. Build changed images and recreate containers. Volumes are untouched.
echo "Running: ${COMPOSE[*]} up -d --build"
"${COMPOSE[@]}" up -d --build

# 3. Health check against the management port from the env file.
control_port=$(grep -E '^CONTROL_PORT=' "$ENV_PATH" | tail -n1 | cut -d= -f2)
control_port="${control_port:-18080}"
url="http://127.0.0.1:${control_port}/healthz"
for i in $(seq 1 30); do
  if curl -fsS "$url" 2>/dev/null | grep -qx ok; then
    echo "Health check passed: $url"
    "${COMPOSE[@]}" ps
    exit 0
  fi
  sleep 10
done

echo "ERROR: server did not become healthy at $url after 5 minutes." >&2
"${COMPOSE[@]}" ps >&2 || true
"${COMPOSE[@]}" logs --tail 100 server admin >&2 || true
exit 1
