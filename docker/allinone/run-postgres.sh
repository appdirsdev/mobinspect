#!/bin/bash
set -e
PG_BINDIR="$(dirname "$(find /usr/lib/postgresql -maxdepth 3 -name postgres | head -1)")"
exec su postgres -c "$PG_BINDIR/postgres -D ${PGDATA:-/var/lib/postgresql/data}"
