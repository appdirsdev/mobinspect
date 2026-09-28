# W2 — Broken flows

The user named four flows: upload → scan → report → PDF, Docker first boot, AI enrichment, dynamic
analysis. Reading the code turned each into concrete defects; this file lists them with the fix.
Items g, f, a, b, c, d, j run before W3 because they change what the image does at runtime;
e, h, i, k run after the release.

Branch: `ws/2-<item>` per item or small group. Gates: G-code per PR; G-e2e; the new
`tests_e2e/flows/*.sh` scripts are part of the DoD.

## a. Air-gap / throttled-link stall — M

Symptom: on a partially connected or slow link, a scan sits "in progress" for minutes inside a
signature-database download.

- `mobinspect/MobInspect/utils.py:278` `is_internet_available()` — add `MOBINSPECT_OFFLINE` (read via `init.env`) that returns `False` immediately, skipping the Google/Baidu probes.
- `utils.py:523` `update_local_db()` — `requests.get(url, stream=True, timeout=(5, 10))`, read with `iter_content` under a 60 s `time.monotonic()` wall clock; on any failure keep the bundled database. `timeout=3` today is a between-bytes timeout, not a total.
- `mobinspect/MobInspect/tools_download.py:111` — `opener.open(req, timeout=30)`.
- `mobinspect/MalwareAnalyzer/views/MalwareDomainCheck.py:95` — literal IPs via `ipaddress` without DNS; the rest through a `ThreadPoolExecutor` with a 3 s per-lookup bound; skip entirely when offline.
- `mobinspect/StaticAnalyzer/views/windows/windows.py:243-247` — `xmlrpc.client.ServerProxy(url, transport=<TimeoutTransport 10 s>)` inside `try/except`, and no module-global `proxy`.
- `mobinspect/MobInspect/security.py:301,319` — remove the process-wide `socket.setdefaulttimeout(5)` / restore pair; pass `timeout=` at the call.

Acceptance: unit tests that point each call at a blackholed address (`10.255.255.1`) and assert it returns within its bound; a scan of `test_files/android.apk` with `MOBINSPECT_OFFLINE=1` completes and its report matches the golden file.

## b. Stuck states — M

- `mobinspect/StaticAnalyzer/views/common/async_task.py:35` `detect_timeout` does fire for django-q's own timeout (the worker enqueues the result before exiting; the monitor sends `post_execute`). It does not fire for a hard kill (OOM, SIGKILL, container restart), which leaves an `EnqueuedTask` in `started` and blocks rescans for the whole timeout window. Add `sweep_stale_tasks()` — `status='started'` older than `Q_CLUSTER['timeout']` + grace → `failed` — called at the top of `async_analysis` and `list_tasks`.
- AI: `mobinspect/StaticAnalyzer/views/common/llm/tasks.py:170` sets `STATUS='running'` with no timestamp; `views.py:226` refuses a retry while `running`. Enrichment runs in a daemon thread (in the qcluster monitor for auto runs, in gunicorn for the manual button), so any restart mid-run leaves the row `running` forever. Add `UPDATED_AT` (auto_now) to `AIEnrichment` (migration `StaticAnalyzer/0005`) and treat `running` older than 2 × `MOBINSPECT_AI_TOTAL_BUDGET` as retryable.

Acceptance: tests that backdate a row and assert the retry path opens; rescan of a hard-killed task is not blocked.

## c. Three names for the analyzer identifier — S

`utils.py:424` reads bare `ANALYZER_IDENTIFIER` first, then the `AdbConnection` row, then
`settings.ANALYZER_IDENTIFIER` (`MOBINSPECT_ANALYZER_IDENTIFIER`). The deploy files set the bare name
(`deploy/systemd/mobinspect.service.d/avd.conf`, `avd-provision.service`, `deploy/scripts/avd-provision.sh:23`,
`deploy/RUNBOOK.md:131`); the scripts set the prefixed one; an old production env used a third,
dead prefix.

Fix (D3): the Integrations-page `AdbConnection` row wins, then `MOBINSPECT_ANALYZER_IDENTIFIER`, then the
bare name with a one-time deprecation warning. Update the four deploy files to the prefixed name.
Acceptance: a precedence test; `git grep -n 'ANALYZER_IDENTIFIER'` shows one canonical name plus the
single deprecation fallback.

## d. adb calls without timeouts — S

`mobinspect/DynamicAnalyzer/views/android/environment.py:579` `system_check` → `communicate(timeout=15)` and kill on
`TimeoutExpired`; `utils.py:436` `adb devices` → `timeout=10`. Acceptance: a fake `adb` that sleeps makes the test return in time.

## e. API error paths that return a dict — M

`print_n_send_error_response(api=True)` (`utils.py:206-208`) returns a plain dict; 107 call sites mix
that with `HttpResponse`. Do not touch them all here (W4.3 unifies). Audit only the API-reachable
sites — the `views/api/*` modules, `apk.py:272` (hard-coded `False` on an API-capable path), the
`static_analyzer.py` entry — and route them through `make_api_response`. Acceptance: every `/api/v1/*`
error path in `tests_e2e/api` returns JSON with the right status.

## f. AI enrichment — M

- `llm/client.py:132` — `keep_alive` is sent as the raw env string; `"-1"` makes Ollama return HTTP 400. Coerce numeric strings to int, pass duration strings through.
- `client.py:40` `_host_is_enclave` resolves with `getaddrinfo` and `requests` resolves again (rebinding window). Resolve once, pin the IP, connect by IP with the `Host` header.
- `tasks.py` — on enrichment failure set the role's `ModelIntegration.last_status='error'` (today it only changes on a manual probe at `RBAC/views.py:555`, so the Integrations page can show "Connected" during an outage).
- `views.py:190-197` — the manual "Run AI Analysis" button requires both `ModelIntegration` rows; allow env-only configuration (`MOBINSPECT_AI_BASE_URL` + model names) to count as configured.
- `settings.py` AI block — default model names `granite4:3b` → `granite4.1:3b` (classify) and `granite4.1:8b` (generate) to match what the image bakes.
- New `manage.py seed_ai_integrations` — upsert the `generate` and `classify` rows from env and run `RBAC.views._apply_model_probe`, so a fresh container shows "Connected" without a manual step. Called from both entrypoints.

Acceptance: the ~419 llm tests plus new ones pass; `tests_e2e/flows/ai_flow.sh` reaches `STATUS=done` on a fresh container.

## g. Docker first boot — M

- `scripts/entrypoint.sh` and `docker/allinone/run-django-init.sh` — run `migrate --noinput` only (a shipped image never runs `makemigrations`; CI's `makemigrations --check` guarantees the tree is complete), then `seed_rbac`, `create_roles`, `bootstrap_admin`, `seed_ai_integrations`. Fix `--log-level=citical` → `info`.
- Admin and RBAC: RBAC decorators bypass for superusers (`RBAC/permissions.py:57-59`, `decorators.py:128`), but the legacy `@permission_required` views (`delete_scan`, `suppress_by_rule`) check Django Groups, which `create_roles` mirrors from RBAC roles. So `create_roles` is mandatory at boot, and `bootstrap_admin` should also `RoleAssignment.get_or_create(user, Administrator)`.
- `docker/docker-compose.yml` — mirror the stack that actually runs on 192.168.3.64: an `ollama` service with a named model volume, an `x-mi-env` anchor with the widened AI timeouts (`READ_TIMEOUT=600`, `TOTAL_BUDGET=1200`, `KEEP_ALIVE=30m`, `CONNECT_TIMEOUT=10`), `healthcheck: disable: true` on the worker (the image `HEALTHCHECK` curls gunicorn, which a worker does not run), `MOBINSPECT_ALLOWED_HOSTS`, and the Postgres password from an `.env` file — never `POSTGRES_PASSWORD=password` in the file.
- `docker/nginx.conf` — `client_max_body_size 550M` (the app allows 500 MB; 256M gives a raw 413 first), add `Host` and `X-Forwarded-Proto`, drop the `443` port map that lies about TLS.
- Both Dockerfiles — install from the committed `poetry.lock` (`poetry install --only main --no-root`), no `poetry lock` at build time.

Acceptance: `docker compose up` from a fresh clone → login, upload, scan, report, PDF with zero manual steps; `tests_e2e/flows/static_flow.sh` and `password.sh` pass.

## h. Query counts — S

`mobinspect/MobInspect/views/home.py:617-630` `.only(...)` omits `ICON_PATH`, so every row costs an extra
query; add it (and the iOS equivalent). `async_task.py:159` `list_tasks` loads logs per row — fetch
them in one `filter(md5__in=…)`. `home.py:1027` API `recent_scans` — cap `page_size` at 100.
Acceptance: `assertNumQueries` tests; the recent page issues ≤ 5 queries.

## i. Restore script and systemd drop-ins — S

`deploy/scripts/restore.sh:24,40` looks for SQLite files; the backup at `deploy/mobinspect-backup:10` is
`pg_dump -Fc`. Rewrite restore around `pg_restore`; rewrite the RUNBOOK disaster-recovery section
(253-279). Rename `deploy/systemd/mobinspect-web.service.d/` → `mobinspect.service.d/` and
`mobinspect-qcluster.service.d/` → `mobinspect-worker.service.d/` so the hardening and secrets
drop-ins actually apply; add `ExecStartPre=… migrate --noinput`. Acceptance: `systemd-analyze verify`;
a documented restore drill.

## j. Django 6 settings leftovers — S

`settings.py:318` `STATICFILES_STORAGE` is ignored since Django 5.1, so whitenoise compression is
off — move to `STORAGES = {"staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"}, …}`.
Delete `USE_L10N` (:291) and the dead `TEMPLATE_DEBUG`; `ENGINE` → `django.db.backends.postgresql`.
Acceptance: `manage.py check --deploy` no longer warns on these; static responses are gzip.

## k. Dynamic analysis — honest DoD — S

The container has no `/dev/kvm`; the emulator lives on another host. The DoD for this flow is:
c and d landed; `/android_dynamic/<md5>` and `/dynamic_report/<md5>` return the 200 "Unavailable" page
with no device; and **if** an AVD is reachable at `MOBINSPECT_ANALYZER_IDENTIFIER` during
verification, `prepare_device` plus one Frida instrumentation smoke pass — otherwise the ledger says
"env-blocked" and does not claim more. `docs/allinone-deploy.md` (W3.15) documents the
`/system`-writable + reboot prerequisite and the `:5555` forwarding pattern.
`tests_e2e/flows/dynamic_boundary.sh` covers the no-device path.
