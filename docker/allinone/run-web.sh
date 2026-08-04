#!/bin/bash
set -e
MOBINSPECT_HOME="${MOBINSPECT_HOME:-/home/mobinspect/.MobInspect}"
READY_MARKER="$MOBINSPECT_HOME/.migrated"

echo "[web] Waiting for migrations to complete..."
for i in $(seq 1 150); do
    [ -f "$READY_MARKER" ] && break
    sleep 2
done
if [ ! -f "$READY_MARKER" ]; then
    echo "[web] Timed out waiting for migrations." >&2
    exit 1
fi

cd /home/mobinspect/mobinspect
exec gunicorn -b 0.0.0.0:8000 "mobinspect.MobInspect.wsgi:application" --workers=1 --threads=10 --timeout=3600 \
    --worker-tmp-dir=/dev/shm --log-level=info --log-file=- --access-logfile=- --error-logfile=- --capture-output
