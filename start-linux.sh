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

# Shared launcher helpers (log/warn, env loading, pg wait, migrations, web)
DJANGO_MANAGE=("$PY" manage.py)
GUNICORN=("$PY" -m gunicorn)
# shellcheck disable=SC1091
source ./scripts/start-common.sh

# Load PostgreSQL env (switches the app from SQLite to Postgres)
load_postgres_env

CLEANUP_NOTE="(PostgreSQL service left running.)"
trap cleanup EXIT INT TERM

# ---- 1. PostgreSQL ---------------------------------------------------------
start_pg_service() {
  log "PostgreSQL not running — starting it (systemd)..."
  sudo systemctl start postgresql
}
wait_for_postgres start_pg_service

# ---- 2. Migrations ----------------------------------------------------------
run_migrations

# ---- 3. django-q qcluster (background scan worker) --------------------------
start_qcluster

# ---- 4. Web server (foreground) ---------------------------------------------
run_web_foreground
