#!/bin/bash
# =============================================================================
# MobInspect — Linux server launcher (no local emulator).
# Static analysis stack: PostgreSQL + qcluster worker + gunicorn web server.
# Dynamic Analysis: point MOBSF_ANALYZER_IDENTIFIER at a remote AVD server,
# e.g.  MOBSF_ANALYZER_IDENTIFIER=<avd-host>:5555 ./start-linux.sh
#
# Usage:
#   ./start-linux.sh                      # http://0.0.0.0:8000
#   HOST=127.0.0.1 PORT=8080 ./start-linux.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-$HOME/MobInspect/.venv/bin/python}"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

# wkhtmltopdf for PDF export, if installed locally
if [[ -x "$HOME/.local/wkhtmltox/bin/wkhtmltopdf" ]]; then
  export MOBSF_WKHTMLTOPDF_BINARY="$HOME/.local/wkhtmltox/bin/wkhtmltopdf"
elif command -v wkhtmltopdf >/dev/null; then
  export MOBSF_WKHTMLTOPDF_BINARY="$(command -v wkhtmltopdf)"
fi

# Load PostgreSQL env (switches the app from SQLite to Postgres)
# shellcheck disable=SC1091
source ./.env.postgres

QCLUSTER_PID=""
log()  { printf "\033[1;36m[start]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[start]\033[0m %s\n" "$*"; }

cleanup() {
  echo
  log "Shutting down..."
  [[ -n "$QCLUSTER_PID" ]] && kill "$QCLUSTER_PID" 2>/dev/null || true
  log "Stack stopped. (PostgreSQL service left running.)"
}
trap cleanup EXIT INT TERM

# ---- 1. PostgreSQL ---------------------------------------------------------
if pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT"; then
  log "PostgreSQL already running — leaving it as-is."
else
  log "PostgreSQL not running — starting it (systemd)..."
  sudo systemctl start postgresql
  for i in $(seq 1 30); do pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" && break; sleep 1; done
  pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" || { warn "PostgreSQL not reachable"; exit 1; }
  log "PostgreSQL is up."
fi

# ---- 2. Migrations ----------------------------------------------------------
log "Applying migrations..."
"$PY" manage.py migrate --noinput >/dev/null 2>&1 || "$PY" manage.py migrate --noinput
log "Database ready."

# ---- 3. django-q qcluster (background scan worker) --------------------------
log "Starting background worker (qcluster)..."
"$PY" manage.py qcluster >/tmp/mobinspect_qcluster.log 2>&1 &
QCLUSTER_PID=$!
log "Worker started (pid $QCLUSTER_PID, logs: /tmp/mobinspect_qcluster.log)."

# ---- 4. Web server (foreground) ---------------------------------------------
log "Starting MobInspect web server → http://$HOST:$PORT  (Ctrl-C to stop everything)"
exec "$PY" -m gunicorn -b "$HOST:$PORT" mobsf.MobSF.wsgi:application \
  --workers=1 --threads=10 --timeout=3600 \
  --log-level=info --log-file=- --access-logfile=- --error-logfile=- --capture-output
