#!/bin/bash
# All-in-one container entrypoint: bootstraps Postgres on first boot, then
# hands off to supervisord which manages postgres/ollama/django/nginx as
# long-running processes for the life of the container.
set -e

MOBINSPECT_HOME="${MOBINSPECT_HOME:-/home/mobinspect/.MobInspect}"
PGDATA="${PGDATA:-/var/lib/postgresql/data}"
PG_BINDIR="$(dirname "$(find /usr/lib/postgresql -maxdepth 3 -name postgres | head -1)")"

export POSTGRES_USER="${POSTGRES_USER:-mobinspect}"
export POSTGRES_DB="${POSTGRES_DB:-mobinspect}"
export POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
export POSTGRES_PORT="${POSTGRES_PORT:-5432}"

mkdir -p "$MOBINSPECT_HOME"
chown mobinspect:mobinspect "$MOBINSPECT_HOME"

# --- Resolve (or generate + persist) the app DB role's password -----------
PG_PASS_FILE="$MOBINSPECT_HOME/postgres-password.txt"
if [ -n "$POSTGRES_PASSWORD" ]; then
    : # operator-supplied, use as-is
elif [ -s "$PG_PASS_FILE" ]; then
    POSTGRES_PASSWORD="$(cat "$PG_PASS_FILE")"
else
    POSTGRES_PASSWORD="$(openssl rand -hex 24)"
    umask 077
    echo -n "$POSTGRES_PASSWORD" > "$PG_PASS_FILE"
    chown mobinspect:mobinspect "$PG_PASS_FILE"
fi
export POSTGRES_PASSWORD

# --- First-boot Postgres init ----------------------------------------------
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "[entrypoint] Initializing PostgreSQL data directory at $PGDATA ..."
    mkdir -p "$PGDATA"
    chown -R postgres:postgres "$PGDATA"
    chmod 700 "$PGDATA"
    su postgres -c "$PG_BINDIR/initdb -D $PGDATA --auth=trust" >/tmp/initdb.log 2>&1 \
        || { cat /tmp/initdb.log; exit 1; }

    echo "listen_addresses = '127.0.0.1'" >> "$PGDATA/postgresql.conf"

    # Bootstrap the app role + database over the local unix socket (trust
    # auth, never exposed outside this container), then tighten TCP auth to
    # password-required before postgres is ever started for real traffic.
    su postgres -c "$PG_BINDIR/pg_ctl -D $PGDATA -o \"-c listen_addresses=''\" -w start"
    su postgres -c "$PG_BINDIR/psql -v ON_ERROR_STOP=1" <<-SQL
        CREATE ROLE "$POSTGRES_USER" WITH LOGIN CREATEDB PASSWORD '$POSTGRES_PASSWORD';
        CREATE DATABASE "$POSTGRES_DB" OWNER "$POSTGRES_USER";
SQL
    su postgres -c "$PG_BINDIR/pg_ctl -D $PGDATA -w stop"

    # Require scram-sha-256 over TCP; leave the local unix socket on trust
    # (only root/postgres inside this same container can reach it) for
    # administrative convenience.
    sed -i '/^host/s/trust$/scram-sha-256/' "$PGDATA/pg_hba.conf"
    echo "[entrypoint] PostgreSQL initialized; app role '$POSTGRES_USER' + database '$POSTGRES_DB' created."
fi
chown -R postgres:postgres "$PGDATA"

# --- AI defaults (Ollama runs in-container; models are baked into the image) ---
export MOBINSPECT_AI_ENABLED="${MOBINSPECT_AI_ENABLED:-1}"
export MOBINSPECT_AI_BASE_URL="${MOBINSPECT_AI_BASE_URL:-http://127.0.0.1:11434}"
export MOBINSPECT_AI_MODEL_GENERATE="${MOBINSPECT_AI_MODEL_GENERATE:-granite4.1:8b}"
export MOBINSPECT_AI_MODEL_CLASSIFY="${MOBINSPECT_AI_MODEL_CLASSIFY:-granite4.1:3b}"
export MOBINSPECT_AI_CONNECT_TIMEOUT="${MOBINSPECT_AI_CONNECT_TIMEOUT:-10}"
export MOBINSPECT_AI_READ_TIMEOUT="${MOBINSPECT_AI_READ_TIMEOUT:-180}"
export MOBINSPECT_AI_TOTAL_BUDGET="${MOBINSPECT_AI_TOTAL_BUDGET:-500}"
export MOBINSPECT_AI_KEEP_ALIVE="${MOBINSPECT_AI_KEEP_ALIVE:-8760h}"

exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
