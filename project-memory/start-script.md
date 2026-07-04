---
name: start-script
description: What start.sh does — the single end-to-end launcher for the MobInspect stack
metadata: 
  node_type: memory
  type: project
  originSessionId: ddb6a3a9-3aa7-4d11-bc01-6d22ba1f4ff1
---

`./start.sh` (repo root) brings up the whole MobInspect stack in order and tears it down on Ctrl-C:
1. **PostgreSQL** — only started if `pg_isready` says it's down; if already running it is left completely as-is (NEVER restarted). On shutdown it is NEVER stopped (only emulator + qcluster are killed).
2. **Android emulator** (`MobInspect_API34`, `-writable-system`), waits for full boot, then `adb connect 127.0.0.1:5555`.
3. **django-q qcluster** — background scan worker (ORM broker on Postgres, no Redis).
4. **gunicorn web server** → http://127.0.0.1:8000 (foreground).

Flags: `./start.sh --no-emulator` (static only), `HOST=0.0.0.0 PORT=8080 ./start.sh`.

Key env it exports: `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`, `MOBSF_ANALYZER_IDENTIFIER=127.0.0.1:5555`, plus sources `.env.postgres`.

Two non-obvious things baked in (see [[dynamic-analysis-fixes]]): MobInspect BLOCKS Django `runserver` → must use gunicorn (as run.sh does); macOS needs `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` or gunicorn workers crash-loop with `+[NSCharacterSet initialize] ... fork()` SIGKILL. There is also a convenience `run-mobinspect.sh` (emulator|server) from earlier. Toolchain in [[toolchain]].
