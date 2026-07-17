#!/usr/bin/env bash
# MobInspect dev launcher — builds CSS, migrates DB, seeds RBAC, and serves
# the UI on the configured port. For production use the systemd units under
# deploy/systemd/ instead.
#
# Usage:
#   ./scripts/start.sh                       # http://127.0.0.1:8001
#   MOBINSPECT_PORT=9000 ./scripts/start.sh  # custom port
#   MOBINSPECT_BIND=0.0.0.0 ./scripts/start.sh  # bind on all interfaces
#
# Ctrl+C stops the UI server.

set -euo pipefail

PORT="${MOBINSPECT_PORT:-8001}"
BIND="${MOBINSPECT_BIND:-127.0.0.1}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
CSS="$ROOT/mobinspect/static/mobinspect/css/dist/app.css"

log()  { printf '\033[1;36m[start]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[start]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[start]\033[0m %s\n' "$*" >&2; exit 1; }

command -v poetry >/dev/null || fail "poetry not found in PATH"

# 1) Tailwind CSS — build if missing.
if [[ ! -f "$CSS" ]]; then
  log "Building Tailwind CSS"
  ./scripts/tailwind-build.sh
fi

# 2) Apply migrations + seed RBAC defaults + bootstrap admin (all idempotent).
log "Applying migrations + seeding RBAC + bootstrapping admin"
MOBINSPECT_DEV=1 poetry run python manage.py migrate --noinput >/dev/null
MOBINSPECT_DEV=1 poetry run python manage.py seed_rbac     >/dev/null
MOBINSPECT_DEV=1 poetry run python manage.py bootstrap_admin

# 3) Free the port — only if a previous MobInspect runserver is holding it.
prev_pid=$(ss -tlnp 2>/dev/null \
  | awk -v p=":$PORT" '$4 ~ p { print $NF }' \
  | grep -oP 'pid=\K[0-9]+' | head -n1 || true)
if [[ -n "${prev_pid:-}" ]]; then
  prev_cmd=$(ps -p "$prev_pid" -o args= 2>/dev/null || true)
  if [[ "$prev_cmd" == *"manage.py runserver"* ]]; then
    log "Stopping prior runserver (pid $prev_pid)"
    kill "$prev_pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      sleep 0.5
      kill -0 "$prev_pid" 2>/dev/null || break
    done
  else
    fail "Port $PORT is in use by an unrelated process (pid $prev_pid). Pick another with MOBINSPECT_PORT=…"
  fi
fi

# 4) Open the browser once the server is up.
URL="http://$BIND:$PORT/"
if command -v xdg-open >/dev/null; then
  ( for _ in $(seq 1 20); do
      sleep 0.5
      curl -sf -o /dev/null "$URL" && { xdg-open "$URL" >/dev/null 2>&1; break; }
    done ) &
  disown
fi

# 5) Start the Django UI server in the foreground.
log "MobInspect UI: $URL"
log "Admin: set MOBINSPECT_ADMIN_PASSWORD before first run, or check"
log "       ~/.MobInspect/initial-admin-password.txt for the generated one."
# --nostatic disables runserver's WSGI-level static handler so WhiteNoise
# middleware (which serves STATIC_ROOT directly) gets the /static/* requests.
exec env MOBINSPECT_DEV=1 MOBINSPECT_DEBUG=1 \
  poetry run python manage.py runserver --nostatic "$BIND:$PORT"
