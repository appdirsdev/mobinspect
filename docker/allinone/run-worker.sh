#!/bin/bash
set -e
MOBINSPECT_HOME="${MOBINSPECT_HOME:-/home/mobinspect/.MobInspect}"
READY_MARKER="$MOBINSPECT_HOME/.migrated"

echo "[worker] Waiting for migrations to complete..."
for i in $(seq 1 150); do
    [ -f "$READY_MARKER" ] && break
    sleep 2
done
if [ ! -f "$READY_MARKER" ]; then
    echo "[worker] Timed out waiting for migrations." >&2
    exit 1
fi

cd /home/mobinspect/mobinspect
exec python3 manage.py qcluster
