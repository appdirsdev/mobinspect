#!/usr/bin/env bash
# =============================================================================
# MobInspect — one-command Ubuntu installer.
#
# Installs EVERYTHING needed to run MobInspect end-to-end — static analysis,
# malware analysis, the web UI, the REST API, PDF export, PostgreSQL, the
# background scan worker — on a fresh Ubuntu 22.04 or 24.04 box.
#
# NOT installed: the Android emulator / AVD (dynamic analysis). Point
# MOBINSPECT_ANALYZER_IDENTIFIER=<avd-host>:5555 at a separate AVD host later.
#
# Idempotent: safe to re-run. Run as a NORMAL user that has sudo (NOT root).
#
#   git clone https://github.com/appdirsdev/mobinspect && cd mobinspect
#   ./scripts/setup-ubuntu.sh
#
# Override defaults via env, e.g.:
#   POSTGRES_PASSWORD=secret MOBINSPECT_ADMIN_PASSWORD=Admin#12345 ./scripts/setup-ubuntu.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_DIR="$(pwd)"

# ---- tunables ---------------------------------------------------------------
PYVER_SERIES="${MI_PYTHON:-python3.13}"      # deadsnakes package name
NODE_VER="${MI_NODE_VERSION:-20.18.1}"
WKHTML_VER="${MI_WKHTMLTOPDF_VERSION:-0.12.6.1-3}"
PG_DB="${POSTGRES_DB:-mobinspect}"
PG_USER="${POSTGRES_USER:-mobinspect}"
PG_HOST="${POSTGRES_HOST:-127.0.0.1}"
PG_PORT="${POSTGRES_PORT:-5432}"
MOBINSPECT_HOME="${MOBINSPECT_HOME_DIR:-$HOME/.MobInspect}"

log()  { printf '\n\033[1;36m[setup] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]  %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[error] %s\033[0m\n' "$*" >&2; exit 1; }

# ---- 0. preflight -----------------------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || die "This installer is for Ubuntu/Linux only."
[[ "$(id -u)" -ne 0 ]] || die "Run as a normal user with sudo, not as root."
command -v sudo >/dev/null || die "sudo is required."
[[ -f manage.py ]] || die "Run this from the MobInspect repo root (git clone first)."
. /etc/os-release 2>/dev/null || true
ARCH="$(dpkg --print-architecture)"          # amd64 | arm64
case "$ARCH" in
  amd64) NODE_ARCH=x64 ;;
  arm64) NODE_ARCH=arm64 ;;
  *) die "Unsupported architecture: $ARCH" ;;
esac
log "Ubuntu ${VERSION_ID:-?} (${VERSION_CODENAME:-?}), arch=$ARCH — installing into $REPO_DIR"

# ---- 1. system packages -----------------------------------------------------
log "Installing system packages (apt)…"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  build-essential pkg-config ca-certificates curl wget unzip xz-utils gnupg \
  git software-properties-common openssl \
  postgresql postgresql-contrib libpq-dev \
  openjdk-17-jdk-headless \
  libmagic1 \
  libssl-dev libffi-dev zlib1g-dev libjpeg-dev libxml2-dev libxslt1-dev \
  fontconfig libxrender1 libxext6 xfonts-75dpi xfonts-base \
  android-tools-adb
JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")"
export JAVA_HOME
log "JAVA_HOME=$JAVA_HOME"
# aapt/aapt2 assist Android resource extraction (androguard covers most cases);
# best-effort so a minimal image without the package doesn't abort the install.
sudo apt-get install -y aapt 2>/dev/null || warn "aapt not in apt — resource extraction falls back to androguard."

# ---- 2. Python 3.13 ---------------------------------------------------------
PYBIN=""
for c in "$PYVER_SERIES" python3.13 python3.12; do
  command -v "$c" >/dev/null 2>&1 && { PYBIN="$(command -v "$c")"; break; }
done
if [[ -z "$PYBIN" ]]; then
  log "Installing $PYVER_SERIES from the deadsnakes PPA…"
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
  sudo apt-get install -y "${PYVER_SERIES}" "${PYVER_SERIES}-venv" "${PYVER_SERIES}-dev"
  PYBIN="$(command -v "$PYVER_SERIES")"
fi
# Ensure the chosen interpreter has venv + dev headers. Ubuntu 24.04 ships
# python3.12 but NOT python3.12-venv, so `python -m venv` would otherwise abort.
PYPKG="$(basename "$PYBIN")"
sudo apt-get install -y "${PYPKG}-venv" "${PYPKG}-dev" 2>/dev/null \
  || sudo apt-get install -y python3-venv python3-dev
log "Using Python: $PYBIN ($("$PYBIN" --version 2>&1))"

# ---- 3. Node (for the Tailwind CSS build) -----------------------------------
NODE_DIR="/opt/nodejs-${NODE_VER}"
if [[ ! -x "$NODE_DIR/bin/node" ]]; then
  log "Installing Node ${NODE_VER} (official tarball)…"
  wget -qO /tmp/node.tar.xz \
    "https://nodejs.org/dist/v${NODE_VER}/node-v${NODE_VER}-linux-${NODE_ARCH}.tar.xz"
  sudo mkdir -p "$NODE_DIR"
  sudo tar -xJf /tmp/node.tar.xz -C "$NODE_DIR" --strip-components=1
  rm -f /tmp/node.tar.xz
fi
export PATH="$NODE_DIR/bin:$PATH"
log "Node: $(node --version)"

# ---- 4. wkhtmltopdf (patched build for full-fidelity PDF export) ------------
if ! command -v wkhtmltopdf >/dev/null 2>&1; then
  log "Installing wkhtmltopdf ${WKHTML_VER}…"
  DEB="wkhtmltox_${WKHTML_VER}.${VERSION_CODENAME}_${ARCH}.deb"
  if wget -qO "/tmp/$DEB" \
      "https://github.com/wkhtmltopdf/packaging/releases/download/${WKHTML_VER}/${DEB}"; then
    sudo apt-get install -y "/tmp/$DEB" || warn "wkhtmltox .deb install failed — PDF export may be limited."
    rm -f "/tmp/$DEB"
  else
    warn "No prebuilt wkhtmltox for ${VERSION_CODENAME}/${ARCH}; falling back to apt."
    sudo apt-get install -y wkhtmltopdf || warn "wkhtmltopdf not installed — PDF export unavailable."
  fi
fi
command -v wkhtmltopdf >/dev/null 2>&1 && log "wkhtmltopdf: $(command -v wkhtmltopdf)"

# ---- 5. PostgreSQL role + database ------------------------------------------
log "Configuring PostgreSQL (db=$PG_DB user=$PG_USER)…"
sudo systemctl enable --now postgresql
# Reuse the password already recorded in .env.postgres on a re-run so the live
# role and the env file can never diverge (keeps the installer idempotent).
if [[ -z "${POSTGRES_PASSWORD:-}" && -f .env.postgres ]]; then
  POSTGRES_PASSWORD="$(sed -n 's/^export POSTGRES_PASSWORD=//p' .env.postgres | head -1)"
fi
: "${POSTGRES_PASSWORD:=$(openssl rand -hex 16)}"
PG_PASS="$POSTGRES_PASSWORD"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 \
  || sudo -u postgres psql -c "CREATE ROLE \"$PG_USER\" LOGIN PASSWORD '$PG_PASS';"
sudo -u postgres psql -c "ALTER ROLE \"$PG_USER\" WITH PASSWORD '$PG_PASS';"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 \
  || sudo -u postgres createdb -O "$PG_USER" "$PG_DB"

# ---- 6. Python virtualenv + dependencies ------------------------------------
log "Creating virtualenv and installing Python dependencies…"
[[ -x .venv/bin/python ]] || "$PYBIN" -m venv .venv
.venv/bin/pip install -q -U pip wheel
.venv/bin/pip install -q "poetry==1.8.4"
.venv/bin/poetry export -f requirements.txt --only main --without-hashes -o /tmp/mi-req.txt
.venv/bin/pip install -q -r /tmp/mi-req.txt
rm -f /tmp/mi-req.txt

# ---- 7. JADX (static-analysis decompiler) -----------------------------------
log "Downloading bundled analysis tools (JADX)…"
mkdir -p "$MOBINSPECT_HOME"
PYTHONPATH="$REPO_DIR" .venv/bin/python mobinspect/MobInspect/tools_download.py "$MOBINSPECT_HOME" \
  || warn "tools_download.py failed — JADX decompilation may be degraded."

# ---- 8. Frontend CSS (Tailwind → css/dist/app.css) --------------------------
log "Building the frontend CSS (Tailwind)…"
npx --yes tailwindcss@3 \
  -i mobinspect/static/mobinspect/css/src/app.css \
  -o mobinspect/static/mobinspect/css/dist/app.css --minify \
  || warn "Tailwind build failed — the UI may render unstyled."

# ---- 9. Environment file ----------------------------------------------------
DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ ! -f .env.postgres ]]; then
  log "Writing .env.postgres…"
  SECRET="$(.venv/bin/python -c 'import secrets;print(secrets.token_urlsafe(50))')"
  ADMIN_PW="${MOBINSPECT_ADMIN_PASSWORD:-$(openssl rand -base64 15 | tr -d '/+=' | cut -c1-16)#1A}"
  cat > .env.postgres <<EOF
# Generated by setup-ubuntu.sh — edit as needed.
export POSTGRES_USER=$PG_USER
export POSTGRES_PASSWORD=$PG_PASS
export POSTGRES_HOST=$PG_HOST
export POSTGRES_PORT=$PG_PORT
export POSTGRES_DB=$PG_DB
export MOBINSPECT_SECRET_KEY=$SECRET
export MOBINSPECT_ALLOWED_HOSTS=${DETECTED_IP:+$DETECTED_IP,}127.0.0.1,localhost
export MOBINSPECT_ADMIN_PASSWORD=$ADMIN_PW
export MOBINSPECT_ASYNC_ANALYSIS=1
export MOBINSPECT_MULTIPROCESSING=thread
export JAVA_HOME=$JAVA_HOME
export PATH=$JAVA_HOME/bin:\$PATH
EOF
  chmod 600 .env.postgres
else
  warn ".env.postgres already exists — leaving it untouched."
fi
# shellcheck disable=SC1091
set -a; . ./.env.postgres; set +a

# ---- 10. Database migrate + RBAC seed + admin -------------------------------
log "Applying migrations and seeding RBAC…"
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py seed_rbac
.venv/bin/python manage.py create_roles
.venv/bin/python manage.py bootstrap_admin
.venv/bin/python manage.py collectstatic --noinput >/dev/null 2>&1 || true

# Belt-and-suspenders: also give the bootstrapped admin the Administrator role.
# A superuser already passes the RBAC checks, but an explicit assignment makes
# the account appear and be manageable in the RBAC UI. Harmless if it no-ops.
.venv/bin/python manage.py shell <<'PY' 2>/dev/null || warn "Could not auto-assign the Administrator role — assign it in the UI."
from django.contrib.auth import get_user_model
try:
    from mobinspect.RBAC.models import Role, RoleAssignment
except Exception:
    Role = RoleAssignment = None
admin = get_user_model().objects.filter(is_superuser=True).order_by('id').first()
if admin and Role and RoleAssignment:
    role = Role.objects.filter(name='Administrator').first()
    if role:
        RoleAssignment.objects.get_or_create(
            user=admin, role=role, defaults={'granted_by': admin})
        print('Administrator role ensured for', admin.username)
PY

# ---- done -------------------------------------------------------------------
cat <<EOF

$(printf '\033[1;32m')============================================================
 MobInspect is installed.
============================================================$(printf '\033[0m')

  Start it (static + malware analysis, no emulator):
      PY=$REPO_DIR/.venv/bin/python ./scripts/start-all.sh --no-emulator
  or bind on all interfaces:
      HOST=0.0.0.0 PORT=8000 PY=$REPO_DIR/.venv/bin/python ./scripts/start-all.sh --no-emulator
  (start-all.sh's default interpreter path assumes ~/MobInspect; the PY= override
   points it at THIS clone's virtualenv.)

  Web UI:   http://${DETECTED_IP:-127.0.0.1}:8000/
  Login:    admin / (see MOBINSPECT_ADMIN_PASSWORD in .env.postgres,
            or $MOBINSPECT_HOME/initial-admin-password.txt if it was generated)

  Dynamic analysis (AVD) is intentionally NOT set up. To enable it later,
  point at a separate emulator host:
      export MOBINSPECT_ANALYZER_IDENTIFIER=<avd-host>:5555

EOF
