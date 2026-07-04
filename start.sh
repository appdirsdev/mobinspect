#!/bin/bash
# =============================================================================
# MobInspect — single end-to-end launcher.
# Brings up the WHOLE stack in the right order and tears it down on Ctrl-C:
#   1. PostgreSQL 16        (Homebrew service)
#   2. Android AVD          (emulator, for Dynamic Analysis)
#   3. django-q qcluster    (background worker for scans/analysis)
#   4. MobInspect web server (foreground → http://127.0.0.1:8000)
#
# Usage:
#   ./start.sh                 # everything (default)
#   ./start.sh --no-emulator   # skip the Android emulator (static analysis only)
#   HOST=0.0.0.0 PORT=8080 ./start.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# ---- config / toolchain paths (from the install) ---------------------------
PY="$HOME/.pyenv/versions/3.13.5/bin/python"
export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:/opt/homebrew/opt/postgresql@16/bin:$PATH"

# macOS: gunicorn forks workers after Objective-C libs init, which macOS
# kills ("+[NSCharacterSet initialize] ... fork()"). This disables that guard.
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

# PDF report export (wkhtmltopdf). Homebrew dropped the formula (upstream
# archived), so it's installed from the official pkg into ~/.local/wkhtmltox.
# MobInspect maps this env var to settings.WKHTMLTOPDF_BINARY.
if [[ -x "$HOME/.local/wkhtmltox/bin/wkhtmltopdf" ]]; then
  export MOBSF_WKHTMLTOPDF_BINARY="$HOME/.local/wkhtmltox/bin/wkhtmltopdf"
fi

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
AVD="${AVD:-MobInspect_API30}"
# Dynamic Analysis target. A local emulator's `emulator-5554` id is NOT
# usable with `adb connect` (MobInspect connects that way), so point it at
# the emulator's TCP adb port instead. This is the fix for
# "Cannot connect to emulator-5554".
EMU_TCP="127.0.0.1:5555"
export MOBSF_ANALYZER_IDENTIFIER="$EMU_TCP"
START_EMULATOR=1
[[ "${1:-}" == "--no-emulator" ]] && START_EMULATOR=0

# Load PostgreSQL env (switches the app from SQLite to Postgres)
# shellcheck disable=SC1091
source ./.env.postgres

EMU_PID=""
QCLUSTER_PID=""

log()  { printf "\033[1;36m[start]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[start]\033[0m %s\n" "$*"; }

cleanup() {
  echo
  log "Shutting down..."
  [[ -n "$QCLUSTER_PID" ]] && kill "$QCLUSTER_PID" 2>/dev/null || true
  if [[ "$START_EMULATOR" == "1" ]]; then
    adb emu kill 2>/dev/null || true
  fi
  log "Stack stopped. (PostgreSQL service left running — 'brew services stop postgresql@16' to stop it.)"
}
trap cleanup EXIT INT TERM

# ---- 1. PostgreSQL ---------------------------------------------------------
# Only start it if it isn't already accepting connections. If it's already
# running, leave it exactly as-is (never restart a live server).
if pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT"; then
  log "PostgreSQL already running — leaving it as-is."
else
  log "PostgreSQL not running — starting it..."
  brew services start postgresql@16 >/dev/null 2>&1 || true
  for i in $(seq 1 30); do pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" && break; sleep 1; done
  pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" || { warn "PostgreSQL not reachable"; exit 1; }
  log "PostgreSQL is up."
fi

# Apply any pending migrations (safe/idempotent)
log "Applying migrations..."
"$PY" -m poetry run python manage.py migrate --noinput >/dev/null 2>&1 || \
  "$PY" -m poetry run python manage.py migrate --noinput
log "Database ready."

# ---- 2. Android emulator ---------------------------------------------------
if [[ "$START_EMULATOR" == "1" ]]; then
  if adb devices 2>/dev/null | grep -q "emulator-.*device"; then
    log "An emulator is already running — reusing it."
  else
    log "Booting Android emulator ($AVD)..."
    nohup "$ANDROID_HOME/emulator/emulator" -avd "$AVD" \
      -writable-system -no-snapshot -no-boot-anim -no-audio \
      -gpu swiftshader_indirect >/tmp/mobinspect_emu.log 2>&1 &
    EMU_PID=$!
    adb start-server >/dev/null 2>&1 || true
    log "Waiting for device to come online..."
    adb wait-for-device
    log "Waiting for full boot (this can take a minute)..."
    for i in $(seq 1 90); do
      [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
      sleep 2
    done
    log "Emulator booted: $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r') / $(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
  fi
  # Register the emulator over TCP so MobInspect's `adb connect $EMU_TCP` works.
  adb connect "$EMU_TCP" >/dev/null 2>&1 || true
  if adb -s "$EMU_TCP" get-state 2>/dev/null | grep -q device; then
    log "Dynamic Analysis target ready at $EMU_TCP"
  else
    warn "Could not register $EMU_TCP — Dynamic Analysis may be unavailable."
  fi
else
  warn "Skipping emulator (--no-emulator). Dynamic Analysis will be unavailable."
fi

# ---- 3. django-q qcluster (background scan worker) -------------------------
log "Starting background worker (qcluster)..."
"$PY" -m poetry run python manage.py qcluster >/tmp/mobinspect_qcluster.log 2>&1 &
QCLUSTER_PID=$!
log "Worker started (pid $QCLUSTER_PID, logs: /tmp/mobinspect_qcluster.log)."

# ---- 4. Web server (foreground) -------------------------------------------
# MobInspect disables Django's dev runserver; use gunicorn (same as run.sh).
log "Starting MobInspect web server → http://$HOST:$PORT  (Ctrl-C to stop everything)"
exec "$PY" -m poetry run gunicorn -b "$HOST:$PORT" mobsf.MobSF.wsgi:application \
  --workers=1 --threads=10 --timeout=3600 \
  --log-level=info --log-file=- --access-logfile=- --error-logfile=- --capture-output
