---
name: release-2026-7
description: "What the release-2026.7 branch contains, credential convention, and security debt"
metadata: 
  node_type: memory
  type: project
  originSessionId: 85e8d82d-ac91-4200-b3a5-995d0479a70e
---

**Branch `release-2026.7`** is the active work branch (off `main`/`9466560`). Contents:
- `7c6dc64` — fixes for all 15 findings from an xhigh code review of `9466560` (launcher trap/exec, `run-mobinspect.sh` MOBINSPECT_DEV + AVD name, frida self-heal + versioned marker, `compare_versions` FILE_NAME fallback, jQuery-free onerror, hosts-refresh keep-previous-ALLOWED_HOSTS, PDF font/wordmark + drop javascript-delay, `.env.postgres` untracked + `.env.postgres.example`, shared launcher lib, dead `_app_header.html` removed).
- `da8635e` — RBAC audit tests made to pass on PostgreSQL (SET CONSTRAINTS ALL IMMEDIATE + vendor-aware DISABLE TRIGGER).
- `b0988db`/`fcfca7d`/`4a4eb63` — the test-coverage campaign, see [[coverage-campaign]].

**Credential convention (important):** the app runs on **admin/admin** — the Postgres role, the MobInspect web admin user, and the local `.env.postgres` (`POSTGRES_USER/PASSWORD=admin`). `.env.postgres` is **gitignored** (as of the review fix) — the admin/admin values are LOCAL ONLY and must never be committed. `.env.postgres.example` holds placeholders. Set the web admin via `MOBINSPECT_ADMIN_USERNAME/PASSWORD` env + `manage.py bootstrap_admin`.

**Security debt (unresolved):** the ORIGINAL `mobsf/mobsf` Postgres creds are still in **public git history** at commit `9466560` (already on GitHub `main`/`mobinspect`). Untracking `.env.postgres` on `release-2026.7` stops future exposure but does NOT purge history — fully removing them needs a history rewrite + force-push + credential rotation. Flagged to the user; not yet done.

**Local dev env:** Python 3.13.5 via pyenv (`~/.pyenv/versions/3.13.5`), poetry venv `mobinspect-btTnr8bA-py3.13`, Postgres 17 on **port 5433** (Homebrew `postgresql@17`), wkhtmltopdf at `~/.local/wkhtmltox/bin` (Rosetta). Launch: `./scripts/start-all.sh --no-emulator` (renamed from root `start.sh` in the 2026-07-21 repo reorg — see [[repo-reorg-2026-07-21]]).

**Running the app manually (not via start-all.sh) — two gotchas:**
1. `manage.py runserver` is **hard-blocked** unless `MOBINSPECT_DEV=1` is set (`manage.py:13`) — prints "We do not allow debug server anymore" and exits. For a quick manual dev server, either set that env var or (closer to prod) run gunicorn directly: `poetry run gunicorn -b 127.0.0.1:8000 mobinspect.MobInspect.wsgi:application --workers=1 --threads=4 --timeout=180`.
2. On macOS, gunicorn workers crash-loop with `objc[pid]: +[NSCharacterSet initialize] ... Crashing instead` (fork-safety issue between gunicorn's worker fork and the Objective-C runtime) unless `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` is exported before starting gunicorn. Async scans also need `poetry run python manage.py qcluster` running in the background (django-q worker) or uploads just sit queued forever.

**Remotes:** `github` = github.com/appdirsdev/mobinspect (reachable). `origin` = Gitea `192.168.3.244:3000` (a different subnet than this Mac's current `192.168.29.x` — unreachable; also a shallow+partial clone, see git-remote quirks).

Device/dynamic-analysis coverage is paused — see [[coverage-campaign]] for why and how to resume.
