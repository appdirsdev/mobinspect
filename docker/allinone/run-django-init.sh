#!/bin/bash
# One-shot per boot: wait for Postgres, migrate, bootstrap admin/roles, then
# touch a marker file that run-web.sh / run-worker.sh wait on before
# starting gunicorn / the django-q worker. Idempotent — safe to run on
# every container start (mirrors the multi-container image's entrypoint.sh).
set -e

MOBINSPECT_HOME="${MOBINSPECT_HOME:-/home/mobinspect/.MobInspect}"
READY_MARKER="$MOBINSPECT_HOME/.migrated"
rm -f "$READY_MARKER"

echo "[django-init] Waiting for Postgres to accept connections..."
pg_ready=0
for i in $(seq 1 60); do
    if su postgres -c "pg_isready -h 127.0.0.1 -p ${POSTGRES_PORT:-5432}" >/dev/null 2>&1; then
        echo "[django-init] Postgres is ready."
        pg_ready=1
        break
    fi
    sleep 2
done
if [ "$pg_ready" -ne 1 ]; then
    # Do NOT fall through to migrate against a not-ready DB: under `set -e` the
    # migrate would abort mid-run and leave no .migrated marker. Exit non-zero
    # so supervisord (autorestart=unexpected) reruns this one-shot cleanly.
    # Realistic trigger: WAL replay on a large, already-populated data volume
    # taking longer than the ~120s wait above.
    echo "[django-init] Postgres not ready after ~120s; exiting for supervisord retry." >&2
    exit 1
fi

cd /home/mobinspect/mobinspect
# mobinspect's login shell is /bin/false (deliberate — no interactive login
# for this service account); su -s overrides just the shell used to run
# these -c commands. Without -s, `su mobinspect -c "..."` silently execs
# /bin/false instead (which ignores -c and exits 1 with no output at all).
su -s /bin/bash mobinspect -c "python3 manage.py makemigrations && python3 manage.py makemigrations StaticAnalyzer && python3 manage.py migrate"
su -s /bin/bash mobinspect -c "python3 manage.py bootstrap_admin"
su -s /bin/bash mobinspect -c "python3 manage.py create_roles"

touch "$READY_MARKER"
chown mobinspect:mobinspect "$READY_MARKER"
echo "[django-init] Migrations + bootstrap complete."

# Best-effort model preload — warms both baked-in Granite models into
# Ollama's memory so the FIRST real AI enrichment request doesn't pay a
# cold-load penalty. Never fails the boot: Ollama might still be starting,
# and GraniteClient itself is fail-closed on every call regardless.
(
    for i in $(seq 1 60); do
        curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
        sleep 2
    done
    for model in "${MOBINSPECT_AI_MODEL_GENERATE:-granite4.1:8b}" "${MOBINSPECT_AI_MODEL_CLASSIFY:-granite4.1:3b}"; do
        echo "[django-init] Preloading $model ..."
        curl -sf http://127.0.0.1:11434/api/generate \
            -d "{\"model\":\"$model\",\"prompt\":\"\",\"keep_alive\":\"${MOBINSPECT_AI_KEEP_ALIVE:-8760h}\"}" \
            >/dev/null 2>&1 || echo "[django-init] Preload of $model failed (non-fatal)."
    done
) &

exit 0
