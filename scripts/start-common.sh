# shellcheck shell=bash
# =============================================================================
# Shared helpers for the MobInspect launchers (start.sh / start-linux.sh).
# Meant to be sourced, not executed. Callers must set, before sourcing:
#   DJANGO_MANAGE  — array invoking "python manage.py" (e.g. ("$PY" manage.py))
#   GUNICORN       — array invoking gunicorn           (e.g. ("$PY" -m gunicorn))
#   HOST / PORT    — web server bind address
# and may define:
#   cleanup_extra()  — platform-specific teardown (e.g. killing the emulator)
#   CLEANUP_NOTE     — appended to the final "Stack stopped." message
# Callers wire the teardown themselves with:  trap cleanup EXIT INT TERM
# =============================================================================

QCLUSTER_PID=""
WEB_PID=""
CLEANED=0

log()  { printf "\033[1;36m[start]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[start]\033[0m %s\n" "$*"; }

# Tears down everything the launcher started. Guarded so the EXIT trap can't
# run it a second time after an INT/TERM already did.
cleanup() {
  if [[ "$CLEANED" == "1" ]]; then return; fi
  CLEANED=1
  echo
  log "Shutting down..."
  [[ -n "$QCLUSTER_PID" ]] && kill "$QCLUSTER_PID" 2>/dev/null || true
  if declare -F cleanup_extra >/dev/null; then cleanup_extra; fi
  log "Stack stopped. ${CLEANUP_NOTE:-}"
}

# Load PostgreSQL env (switches the app from SQLite to Postgres)
load_postgres_env() {
  if [[ ! -f ./.env.postgres ]]; then
    warn "Missing .env.postgres — copy .env.postgres.example to .env.postgres and set real credentials."
    exit 1
  fi
  # shellcheck disable=SC1091
  source ./.env.postgres
}

# wait_for_postgres <service-start command...>
# Only starts the service if Postgres isn't already accepting connections. If
# it's already running, leave it exactly as-is (never restart a live server).
wait_for_postgres() {
  if pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT"; then
    log "PostgreSQL already running — leaving it as-is."
    return
  fi
  "$@"
  for i in $(seq 1 30); do pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" && break; sleep 1; done
  pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" || { warn "PostgreSQL not reachable"; exit 1; }
  log "PostgreSQL is up."
}

# Apply any pending migrations (safe/idempotent)
run_migrations() {
  log "Applying migrations..."
  "${DJANGO_MANAGE[@]}" migrate --noinput >/dev/null 2>&1 || \
    "${DJANGO_MANAGE[@]}" migrate --noinput
  log "Database ready."
}

start_qcluster() {
  log "Starting background worker (qcluster)..."
  "${DJANGO_MANAGE[@]}" qcluster >/tmp/mobinspect_qcluster.log 2>&1 &
  QCLUSTER_PID=$!
  log "Worker started (pid $QCLUSTER_PID, logs: /tmp/mobinspect_qcluster.log)."
}

# Run gunicorn as a foreground child — NOT exec, which would replace the shell
# and make the cleanup trap unreachable. INT/TERM are forwarded to gunicorn and
# the EXIT trap runs cleanup no matter how the wait ends.
run_web_foreground() {
  log "Starting MobInspect web server → http://$HOST:$PORT  (Ctrl-C to stop everything)"
  "${GUNICORN[@]}" -b "$HOST:$PORT" mobsf.MobSF.wsgi:application \
    --workers=1 --threads=10 --timeout=3600 \
    --log-level=info --log-file=- --access-logfile=- --error-logfile=- --capture-output &
  WEB_PID=$!
  trap 'kill "$WEB_PID" 2>/dev/null || true' INT TERM
  local rc=0
  wait "$WEB_PID" || rc=$?
  # If a signal interrupted the wait above, wait again for gunicorn to finish.
  wait "$WEB_PID" 2>/dev/null || true
  exit "$rc"
}
