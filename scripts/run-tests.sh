#!/usr/bin/env bash
# =============================================================================
# MobInspect — run the branch's deterministic test suite against an
# ALREADY-RUNNING PostgreSQL service. Portable across Linux and macOS.
#
# It NEVER starts or manages Postgres — the service is expected to already be
# running (systemd on Linux, brew on macOS, a service container in CI). This
# script only CHECKS that it is reachable, then runs the tests.
#
# Suite: RBAC / permissions, API auth, user management, and the static-analysis
# unit tests our changes touch. Excludes device/emulator/Frida, the real
# Android toolchain, full integration scans, and network probes.
#
# Usage:
#   ./scripts/run-tests.sh                    # full deterministic suite
#   ./scripts/run-tests.sh mobsf/RBAC -x      # custom pytest args/subset
#   PYTEST="python -m pytest" ./scripts/run-tests.sh   # override the runner
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

# ---- Postgres env (POSTGRES_USER/PASSWORD/HOST/PORT/DB) ----------------------
# Local runs read .env.postgres; CI passes the vars in the job environment.
if [[ -f ./.env.postgres ]]; then
  # shellcheck disable=SC1091
  source ./.env.postgres
fi
POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

# pg_isready lives in the Postgres bin dir, which isn't always on PATH.
# Add the common Linux + macOS locations so the check works out of the box.
for pgbin in \
  /opt/homebrew/opt/postgresql@16/bin \
  /usr/local/opt/postgresql@16/bin \
  /usr/lib/postgresql/*/bin \
  /usr/pgsql-*/bin; do
  [[ -d "$pgbin" ]] && PATH="$pgbin:$PATH"
done

# ---- Just CHECK the Postgres service is up (never start it) -----------------
if command -v pg_isready >/dev/null 2>&1; then
  if ! pg_isready -q -h "$POSTGRES_HOST" -p "$POSTGRES_PORT"; then
    echo "ERROR: PostgreSQL is not reachable at ${POSTGRES_HOST}:${POSTGRES_PORT}." >&2
    echo "       This script only checks the service; start it first, e.g.:" >&2
    echo "         Linux:  sudo systemctl start postgresql" >&2
    echo "         macOS:  brew services start postgresql@16" >&2
    exit 1
  fi
  echo "[tests] PostgreSQL is up at ${POSTGRES_HOST}:${POSTGRES_PORT}."
else
  echo "[tests] pg_isready not found — skipping the pre-check; pytest will" >&2
  echo "        fail fast if PostgreSQL at ${POSTGRES_HOST}:${POSTGRES_PORT} is down." >&2
fi

# ---- Test runner ------------------------------------------------------------
# Default to poetry; override with PYTEST for a bare venv (e.g. the Linux
# server: PYTEST="$HOME/MobInspect/.venv/bin/python -m pytest").
PYTEST="${PYTEST:-poetry run pytest}"

DEFAULT_PATHS=(
  mobsf/RBAC
  mobsf/Analytics/tests
  mobsf/MobSF/views/test_cov_authorization.py
  mobsf/MobSF/views/test_cov_home.py
  mobsf/MobSF/views/test_cov_saml2.py
  mobsf/MobSF/views/api/test_cov_api_static_analysis.py
  mobsf/StaticAnalyzer/views/common/test_cov_suppression.py
  mobsf/StaticAnalyzer/views/common/test_cov_shared_func.py
  mobsf/StaticAnalyzer/views/common/test_cov_shared_func2.py
  mobsf/StaticAnalyzer/views/test_cov_comparer.py
  mobsf/StaticAnalyzer/views/test_cov_sast_engine.py
)

echo "[tests] Running: $PYTEST ${*:-<deterministic suite>}"
if [[ $# -gt 0 ]]; then
  exec $PYTEST "$@"
else
  exec $PYTEST "${DEFAULT_PATHS[@]}" -p no:cacheprovider -q
fi
