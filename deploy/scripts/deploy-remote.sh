#!/usr/bin/env bash
#
# Remote deploy script for Tunnel Control. Runs on the Linux server inside
# the repo checkout (usually /opt/tunnel-control).
#
# Safe by design:
#   - Never runs `docker compose down -v` or removes volumes: the named
#     external volumes postgres-data / redis-data survive every redeploy.
#   - Optionally takes a PostgreSQL dump before touching the stack.
#   - Only uses `up -d --build`, which recreates changed containers without
#     deleting data.
#
set -euo pipefail

APP_DIR="${DEPLOY_DIR:-/opt/tunnel-control}${DEPLOY_SUBDIR:+/$DEPLOY_SUBDIR}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose.yaml}"
ENV_FILE="deploy/.env"
BACKUP_ENABLED="${BACKUP_ENABLED:-1}"
BACKUP_KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/deploy/backups}"

cd "$APP_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $APP_DIR/$ENV_FILE is missing. Copy deploy/.env.example to deploy/.env and fill in the secrets before deploying." >&2
  exit 1
fi

COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE")

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

# 3. Health check against the management port from deploy/.env.
control_port=$(grep -E '^CONTROL_PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2)
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
