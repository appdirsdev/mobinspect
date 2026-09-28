# W3 — All-in-one release

Deliverable: `mobinspect-allinone:<ver>` (linux/amd64) — Postgres 15, Ollama with `granite4.1:3b`
and `granite4.1:8b` baked into the image, gunicorn, the django-q worker and nginx under supervisord,
three named volumes for state — built from a fresh clone on the build host, verified from a fresh
container, and shipped as `mobinspect-allinone-<ver>-amd64.tar.gz.gpg` (D4: the archive is the
password-protected artefact; the app's own login has had no default credentials since
`bootstrap_admin` replaced the seeded user).

Base: `docker/allinone/` as merged in W0.1. Read `project-memory/allinone-docker-build.md` first —
it records the build gotchas (`su -s /bin/bash`, `pkill -x ollama`, the QEMU `ollama pull` failure that
`--build-context ollama-cache=` avoids, `chown` before `useradd`) and the E2E harness.

Branch: `ws/3-allinone`. Gates: G-code, G-e2e, **G-image** (the whole of it).

## Tasks

| # | Task | Files | Size |
|---|---|---|---|
| 3.1 | Reproducible build: install from the committed `poetry.lock`; pin the Ollama installer (`OLLAMA_VERSION`) and the Poetry version; no `makemigrations` at boot (W2.g). | `docker/allinone/Dockerfile`, `run-django-init.sh` | S |
| 3.2 | Postgres password reconciliation: when `PG_VERSION` exists and `$MOBINSPECT_HOME/postgres-password.txt` is present, `ALTER ROLE … PASSWORD` over the trust unix socket, so a rotated or restored file never bricks boot. | `entrypoint.sh` | S |
| 3.3 | Admin password: support `MOBINSPECT_ADMIN_PASSWORD_FILE` (Docker secret) in `bootstrap_admin` (`init.py:163-229`); when neither env nor file is set, print the generated password **once** in a clearly framed banner and persist it 0600; document `docker exec … cat …/initial-admin-password.txt`. | `init.py`, docs | S |
| 3.6 | Rate limits behind the local proxy: nginx sends `X-Real-IP $remote_addr`; settings use `RATELIMIT_IP_META_KEY='HTTP_X_REAL_IP'` when `MOBINSPECT_BEHIND_PROXY=1`; the entrypoint sets that flag. Otherwise every client shares one `127.0.0.1` bucket and one bad login locks everyone out for a minute. | `nginx.conf`, `settings.py`, `entrypoint.sh` | S |
| 3.7 | `ALLOWED_HOSTS` ergonomics: append the container hostname and IP automatically; print a fail-fast banner when `MOBINSPECT_ALLOWED_HOSTS` is unset (LAN access otherwise 400s); `MOBINSPECT_PORT` defaults to 80 in this image. | `entrypoint.sh`, docs | S |
| 3.8 | Close `/tests/` (`urls.py:504` → `StaticAnalyzer/tests.py:563`): it runs the full self-test suite unauthenticated. Wrap with `login_required` + `require_permission('settings.manage')`. | 2 files | S |
| 3.9 | `docker/allinone/healthcheck.sh`: `pg_isready`, `curl 127.0.0.1:11434/api/tags`, `curl /healthz/` (200, `degraded` for adb is fine), `pgrep -f qcluster`, `nginx -t`; wire as the image `HEALTHCHECK`. Add `[unix_http_server]` + `[supervisorctl]` so `supervisorctl status` works. | 2 files | S |
| 3.10 | Disk guard + retention (2026-08-05 RCA: a full disk crashed Postgres mid-decompile; artefacts are ~15× the APK): refuse uploads/scans with a friendly 507 when free space under `UPLD_DIR` is below `MOBINSPECT_MIN_FREE_GB` (default 5); `manage.py prune_scans --older-than N --keep-latest M` that removes `uploads/<md5>/` artefacts and keeps the DB rows + report; document a cron/`docker exec` line and a sizing table. | `home.py`, new command, docs | M |
| 3.11 | Offline assets: the PDF templates load Google Fonts, `base/base_layout.html:21,23` loads fonts + ionicons from CDNs (delete that dead template in W4.4; fix the PDF templates here using the already self-hosted Inter/Albert Sans). Entrypoint defaults `MOBINSPECT_OFFLINE=1`. | PDF templates, `entrypoint.sh` | S |
| 3.12 | Pre-stage `frida-server` for android x86_64 + arm64 with SHA-256 pins and `MOBINSPECT_FRIDA_VERIFY=1` (D5; ~200 MB; only useful with an external AVD). | `Dockerfile`, `dependencies.sh` | S |
| 3.13 | `scripts/build-allinone.sh`: checks the host (x86_64 Linux, Docker, ≥60 GB free, `~/.ollama/models` has both Granite manifests), then runs the `buildx` command from `00-contract.md` §5; version from `pyproject.toml` (D6: bump to `2026.9.0`). | new script | S |
| 3.14 | `scripts/release-allinone.sh <ver>`: `docker save mobinspect-allinone:<ver> \| gzip` → `mobinspect-allinone-<ver>-amd64.tar.gz`; `sha256sum` sidecar; `gpg --symmetric --cipher-algo AES256 --output ….tar.gz.gpg` with the passphrase prompted (never in env, never written); prints the load instructions. The `.gpg` file is what gets distributed. | new script | S |
| 3.15 | `docs/allinone-deploy.md`: decrypt + `docker load`; the `docker run` line with the three named volumes and `-p 80:80 -p 1337:1337`; env table; first login / password retrieval; `MOBINSPECT_ALLOWED_HOSTS`; backup (`docker exec … pg_dump -Fc` + tar of the home volume) and restore; upgrade (new image, same volumes, `migrate` runs at boot); disk sizing; AVD prerequisites and `:5555` forwarding. | docs | M |
| 3.16 | Fresh-image E2E (reuse the harness in `project-memory/allinone-docker-build.md`): login; APK → report → scorecard → PDF; IPA report; JSON-body API upload → 200; AI `STATUS=done` + Dashboard button visible; Viewer key → 403; `docker restart` and `docker rm` + recreate keep scans and files; 520 MB upload → app 400, 560 MB → nginx 413. Record each step's evidence in `PROGRESS.md`. | — | M |
| 3.17 | CI: `docker-allinone.yml` on `workflow_dispatch` that builds with an empty `ollama-cache` build context as a compile check only (GitHub runners have ~14 GB free; a model-baked image cannot be built there). The real build is manual on the build host. Factor `scripts/dependencies.sh` + a new `scripts/install-jadx.sh` so both Dockerfiles share the steps. | workflow, scripts | S |

Optional follow-ups, explicitly **not** in the DoD: `MOBINSPECT_HTTP_BASIC_AUTH=1` (nginx `auth_basic`
with `/healthz/`, `/readyz/`, `/api/` exempt — `Authorization` is also the API-key header) and
`MOBINSPECT_TLS=1` (self-signed cert at first boot, port of `deploy/mobinspect-gencert`, nginx 443 +
80→443, `MOBINSPECT_BEHIND_TLS=1`).

## Definition of Done

G-image (`00-contract.md` §5) passes end to end from a fresh `git clone` on the build host;
`scripts/release-allinone.sh` produces the three files; on a **different** clean Docker host,
`gpg --decrypt … | gunzip | docker load` followed by the documented `docker run` with only
`MOBINSPECT_ADMIN_PASSWORD` and `MOBINSPECT_ALLOWED_HOSTS` reaches `healthy` and completes 3.16.
