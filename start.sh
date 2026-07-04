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

# Shared launcher helpers (log/warn, env loading, pg wait, migrations, web)
DJANGO_MANAGE=("$PY" -m poetry run python manage.py)
GUNICORN=("$PY" -m poetry run gunicorn)
# shellcheck disable=SC1091
source ./scripts/start-common.sh

# Load PostgreSQL env (switches the app from SQLite to Postgres)
load_postgres_env

EMU_PID=""

cleanup_extra() {
  if [[ "$START_EMULATOR" == "1" ]]; then
    adb emu kill 2>/dev/null || true
  fi
}
CLEANUP_NOTE="(PostgreSQL service left running — 'brew services stop postgresql@16' to stop it.)"
trap cleanup EXIT INT TERM

# ---- 1. PostgreSQL ---------------------------------------------------------
start_pg_service() {
  log "PostgreSQL not running — starting it..."
  brew services start postgresql@16 >/dev/null 2>&1 || true
}
wait_for_postgres start_pg_service

# Apply any pending migrations (safe/idempotent)
run_migrations

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
start_qcluster

# ---- 4. Web server (foreground) -------------------------------------------
# MobInspect disables Django's dev runserver; use gunicorn (same as run.sh).
run_web_foreground
