#!/usr/bin/env bash
# =============================================================================
# MobInspect — single cross-platform launcher (macOS + Linux).
# Brings up the stack in order and tears it down on Ctrl-C:
#   1. PostgreSQL      — CHECKED, and started only if down
#                        (brew on macOS, systemd on Linux). A running server
#                        is left exactly as-is — never restarted.
#   2. Android AVD     — macOS only, for Dynamic Analysis (--no-emulator skips).
#                        On Linux, point MOBSF_ANALYZER_IDENTIFIER at a remote AVD.
#   3. django-q qcluster — background worker for scans/analysis.
#   4. MobInspect web server (gunicorn, foreground → http://HOST:PORT).
#
# Usage:
#   ./start.sh                 # everything (emulator on macOS)
#   ./start.sh --no-emulator   # static analysis only
#   HOST=0.0.0.0 PORT=8080 ./start.sh
#   PY=/path/to/python ./start.sh          # override the interpreter
#   USE_POETRY=0 ./start.sh                 # run $PY directly (no `poetry run`)
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

OS="$(uname -s)"
START_EMULATOR=1
[[ "${1:-}" == "--no-emulator" ]] && START_EMULATOR=0

# ---- platform config -------------------------------------------------------
if [[ "$OS" == "Darwin" ]]; then
  # macOS dev box: pyenv interpreter + poetry virtualenv, local emulator.
  PY="${PY:-$HOME/.pyenv/versions/3.13.5/bin/python}"
  USE_POETRY="${USE_POETRY:-1}"
  export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  export ANDROID_SDK_ROOT="$ANDROID_HOME"
  export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:/opt/homebrew/opt/postgresql@16/bin:$PATH"
  # macOS kills workers forked after Objective-C init; disable that guard.
  export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
  HOST="${HOST:-127.0.0.1}"
  CLEANUP_NOTE="(PostgreSQL service left running — 'brew services stop postgresql@16' to stop it.)"
  start_pg_service() {
    log "PostgreSQL not running — starting it (brew)..."
    brew services start postgresql@16 >/dev/null 2>&1 || true
  }
else
  # Linux server: venv interpreter, no local emulator (use a remote AVD).
  PY="${PY:-$HOME/MobInspect/.venv/bin/python}"
  USE_POETRY="${USE_POETRY:-0}"
  HOST="${HOST:-0.0.0.0}"
  START_EMULATOR=0
  # Make pg_isready reachable regardless of the login PATH.
  for pgbin in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin; do
    [[ -d "$pgbin" ]] && PATH="$pgbin:$PATH"
  done
  export PATH
  CLEANUP_NOTE="(PostgreSQL service left running.)"
  start_pg_service() {
    log "PostgreSQL not running — starting it (systemd)..."
    sudo systemctl start postgresql
  }
fi
PORT="${PORT:-8000}"

# wkhtmltopdf for PDF export (both platforms).
if [[ -x "$HOME/.local/wkhtmltox/bin/wkhtmltopdf" ]]; then
  export MOBSF_WKHTMLTOPDF_BINARY="$HOME/.local/wkhtmltox/bin/wkhtmltopdf"
elif command -v wkhtmltopdf >/dev/null 2>&1; then
  export MOBSF_WKHTMLTOPDF_BINARY="$(command -v wkhtmltopdf)"
fi

# ---- how we invoke Django / gunicorn ---------------------------------------
if [[ "$USE_POETRY" == "1" ]]; then
  DJANGO_MANAGE=("$PY" -m poetry run python manage.py)
  GUNICORN=("$PY" -m poetry run gunicorn)
else
  DJANGO_MANAGE=("$PY" manage.py)
  GUNICORN=("$PY" -m gunicorn)
fi

# Shared launcher helpers (log/warn, env loading, pg wait, migrations, web).
# shellcheck disable=SC1091
source ./scripts/start-common.sh

# Load PostgreSQL env (switches the app from SQLite to Postgres).
load_postgres_env

# ---- Dynamic Analysis target (macOS local emulator) ------------------------
EMU_PID=""
AVD="${AVD:-MobInspect_API30}"
# A local emulator's `emulator-5554` id is NOT usable with `adb connect`
# (MobInspect connects that way), so target the emulator's TCP adb port.
EMU_TCP="127.0.0.1:5555"
if [[ "$START_EMULATOR" == "1" ]]; then
  export MOBSF_ANALYZER_IDENTIFIER="${MOBSF_ANALYZER_IDENTIFIER:-$EMU_TCP}"
fi

cleanup_extra() {
  if [[ "$START_EMULATOR" == "1" ]]; then adb emu kill 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# ---- 1. PostgreSQL (check; start only if down) -----------------------------
wait_for_postgres start_pg_service

# ---- 2. Migrations (safe/idempotent) ---------------------------------------
run_migrations

# ---- 3. Android emulator (macOS only) --------------------------------------
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
elif [[ "$OS" == "Darwin" ]]; then
  warn "Skipping emulator (--no-emulator). Dynamic Analysis will be unavailable."
else
  warn "Linux: no local emulator. Set MOBSF_ANALYZER_IDENTIFIER=<avd-host>:5555 for Dynamic Analysis."
fi

# ---- 4. django-q qcluster (background scan worker) -------------------------
start_qcluster

# ---- 5. Web server (foreground) -------------------------------------------
run_web_foreground
