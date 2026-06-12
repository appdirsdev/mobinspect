# MobInspect — Multi-Team Audit Report

*Prepared for: Vipin (Appdirs) — June 2026*
*Scope: MobInspect fork of MobSF at `/home/ubuntu/Desktop/Mobile-Security-Framework-MobSF`, deployed at `192.168.2.118:8001`*

---

## Executive summary

MobInspect is a credible, working fork of Mobile Security Framework (MobSF) with a thoughtful Appdirs-added layer (RBAC, Analytics, Tailwind rebrand, three systemd units, a real RUNBOOK) sitting on top of a mature but legacy upstream. The engineering instincts are good — the RBAC module is the highest-quality code in the repo (atomic ApiKey lookup, privilege-escalation guard, append-only audit table by convention) and the deployment shows operational learning (recent commits fix real production gotchas with runbook entries). But the fork is mid-pivot, and the production posture is "developer laptop that survives a reboot," not "production security product." For an Appdirs-branded commercial offering, the gap between the code on disk and what a real customer can buy/install/trust is the central business risk.

The single most important finding, independently raised by Security, Coder, and Code Auditor and verified by adversarial review, is an **authorization bypass on the entire `/api/v1/*` surface**: the legacy `permission_required(..., api=True)` decorator short-circuits and returns the view unwrapped whenever called from the API auth path, and the new RBAC `@require_permission` is not applied to any API endpoint. Net effect: any valid API key — including a "Viewer" per-user key — can hit `execute_adb`, `frida_instrument`, `delete_scan`, `mobsfy`, `ssh_execute`, and `global_proxy` with full effect. Combined with the unsanitized `cmd` parameter in `execute_adb` / `ssh_execute`, this is functionally remote code execution against the managed AVD as an authenticated viewer. RBAC outside of the RBAC/Analytics admin views is theatre.

The other top risks: (1) **production is plaintext HTTP on `0.0.0.0:8001` with `ALLOWED_HOSTS=['*']`, no Secure cookies, no HSTS, no rate limit, default seeded `mobsf/mobsf` superuser and a RUNBOOK that ships `changeme123` as the bootstrap password** — auditable in any sales/diligence/security-review conversation; (2) **SQLite in default delete-mode with `busy_timeout=0` and a single gunicorn worker running synchronous scans** means concurrent users immediately hit `database is locked` and slow-loris uploads can pin the entire UI for 60 minutes (`--timeout 3600`), with one OOM-kill and one timeout-SIGKILL already in the journal; (3) **zero unit tests for any Appdirs-added code (RBAC, Analytics, API middleware, env shim)** — exactly the surface that ships fork-specific behavior — combined with no CI on the Gitea-hosted `mobinspect` branch.

The top strengths are real and worth preserving: (a) the **RBAC module is well-designed** (SHA-256-hashed API keys with constant-time compare, atomic active-filter lookup, privilege-escalation guard in `role_assign`, audit log on grants/denials/role mutations); (b) **documentation discipline is unusually strong for a 14-day fork** — 11 numbered docs, 5 ADRs, a working architecture mermaid, and a RUNBOOK that captures real production gotchas with one-line evidence-based fixes; (c) the **recent deploy-fix commits demonstrate a healthy operational learning loop** (StaticAnalyzer migrations shipped, MOBSF_ADB_BINARY drop-in, AVD writable-system, all with runbook updates). The instinct is right; it just needs to be applied to the security boundary and the production posture, not only to deployment plumbing.

Recommended 30/60/90-day plan in brief: **30 days** — close the API auth bypass, put nginx+TLS in front of gunicorn, fix the half-finished settings (drop `MIDDLEWARE_CLASSES`/`ALLOWED_HOSTS='*'`/dead `SessionAuthenticationMiddleware`), enable SQLite WAL + `MOBSF_ASYNC_ANALYSIS=1` on the web unit, and ship a minimal `/healthz`. **60 days** — write the missing RBAC/Analytics test suite, wire Gitea Actions CI, ship a nightly backup of `~/.MobInspect/`, finish the brand-leakage fixes (PDF logos, SECURITY.md, update-check URL, pyproject metadata), bundle frida-server binaries with SHA256 verification. **90 days** — finish the Tailwind migration of the scan/dynamic report templates, pick one authorization system and retire the other, ship SARIF/JUnit export, and decide the GPL-3.0 monetization posture with outside counsel.

---

## Scorecard

| Domain | Score | Why |
|---|---|---|
| Code quality (Appdirs-added) | 3/5 | RBAC module is well-designed and idiomatic; Analytics is small and clean. But zero tests, half-finished env shim (5 vars rebranded, 80 still hardcoded `MOBSF_*`), and ~46 broad `except Exception:` blocks. |
| Code quality (inherited core) | 2/5 | Dead Django settings (`MIDDLEWARE_CLASSES`, `SessionAuthenticationMiddleware`, `USE_L10N`), Python-2 `e.message`, `'…' % path` with no `%s`, dual `has_permission` functions, side-effecting `get_adb()`. |
| Security posture | 1/5 | API auth bypass, unsanitized `execute_adb`/`ssh_execute`, plaintext HTTP, `ALLOWED_HOSTS=['*']`, default creds, no rate limiting on API, no HSTS/Secure cookies. RBAC is well-designed but unused outside its own views. |
| Operations / NOC | 1/5 | Single gunicorn worker, SQLite delete-mode with `busy_timeout=0`, no `/healthz`, no backups, no logrotate, no TLS, no monitoring, `TimeoutStopSec=30` vs `--timeout 3600` causes SIGKILLs mid-scan, one OOM-kill in journal. |
| DevOps / deployment | 2/5 | Three systemd units exist with a real RUNBOOK; recent commits show genuine operational learning. But no hardening (no `MemoryMax`/`ProtectSystem`/firewall), upstream docker workflows still push to MobSF Hub, secrets in markdown. |
| Audit / SOC readiness | 2/5 | AuditEvent model exists with a sensible schema and a privilege-escalation guard. But login/logout/user-create/delete/password-change are NOT audited, no SIEM forwarder, append-only is convention-only (no hash chain, no DB trigger), no backup, no IR runbook. |
| Product polish | 2/5 | Home/scans-list/AppSec scorecard/Analytics/auth pages are Tailwind. But scan-report and entire dynamic-analyzer surface (~16 templates) still render in AdminLTE. Every exported PDF says "MobSF". |
| Documentation | 4/5 | docs/00-09 + 5 ADRs + RUNBOOK is genuinely above-bar for a 14-day fork. Material asset for diligence. Marred only by README pointing at private LAN URLs and one cross-doc inconsistency (Pixel 6/Android 13 vs Pixel 4/API 30). |
| Test coverage | 1/5 | Zero tests for RBAC, Analytics, env shim, API middleware. `tests.py` in DynamicAnalyzer and MalwareAnalyzer are 0 bytes. Only StaticAnalyzer has a single integration test file. |
| Commercial readiness | 1/5 | No marketing site, no pricing, no `support@appdirs` contact, no SARIF/JUnit export, no OIDC, no webhooks, no public hosted demo, GPL-3.0 monetization path unaddressed. |

---

## Critical findings (P0 — fix immediately)

### C1. API auth bypass: every `/api/v1/*` skips RBAC and the legacy `permission_required` decorator
- **Area:** `mobsf/MobSF/views/authorization.py:62-65` + every wrapper in `mobsf/MobSF/views/api/api_android_dynamic_analysis.py`
- **Evidence:** `permission_required` returns the view unwrapped whenever called with `api=True`. Every API wrapper passes `True` (e.g. `operations.execute_adb(request, True)` at api_android_dynamic_analysis.py:95, `take_screenshot` at :82, `frida instrument` at :196, `delete_scan`, `mobsf_ca`, `global_proxy`, `mobsfy`). No `@require_permission` is applied anywhere in `mobsf/MobSF/views/api/` (verified: grep returns 0 hits). Confirmed by adversarial review as **critical**.
- **Impact:** Any holder of a per-user `ApiKey` — including a Viewer role's key — has full Administrator-equivalent capability over the API surface, including arbitrary `adb shell` (see C2), Frida instrumentation, scan deletion, CA injection, proxy reconfiguration, SSH-exec to jailbroken iOS devices. RBAC roles are decorative for API consumers.
- **Fix:** Remove the `if api: return view(...)` short-circuit. Migrate `/api/v1/*` endpoints to `@require_permission` from `mobsf.RBAC.decorators` (which already honors `request.api_user` via `effective_user`). Add an integration test asserting an API-key user without `scan.delete` gets 403 on `/api/v1/delete_scan`.
- **Effort:** medium (decorator swap + minimal regression test)

### C2. `execute_adb` accepts arbitrary adb shell with no input validation
- **Area:** `mobsf/DynamicAnalyzer/views/android/operations.py:102-124`
- **Evidence:** `execute_adb` reads `request.POST['cmd']`, splits on space, appends to `[adb, -s, <device>]` and shells out. No `cmd_injection_check`, no allowlist. Sibling `mobsfy()` at line 73 DOES call `cmd_injection_check` — the omission is asymmetric, not by design. Reachable at `/execute_adb/` (urls.py:319) and `/api/v1/android/adb_command` (urls.py:127). Production AVD runs with `-writable-system` + `adb root`, so this is root-on-system inside the guest plus tunneled access to the host via `adb forward`/`reverse`. `subprocess.Popen` is called with `shell=False`, so the precise vector is unrestricted adb-subcommand selection (push, install, pull, forward, shell) rather than classical metachar injection — the recommended fix is therefore an argv/verb whitelist, not a metachar filter.
- **Fix:** Drop the endpoint or restrict to a small allowlist (`shell pm list packages`, `shell getprop`). Gate with a new `dynamic.adb.shell` dangerous permission. Apply the same treatment to `ssh_execute` / `ssh_execute_device` in `mobsf/DynamicAnalyzer/views/ios/corellium_instance.py:695-724` and `device/dynamic_analyzer.py:240-259`, which forward raw input to `paramiko.exec_command`.
- **Effort:** small

### C3. Production is plaintext HTTP on `0.0.0.0:8001` with no Secure cookies and a wildcard `ALLOWED_HOSTS`
- **Area:** `deploy/systemd/mobinspect.service:18` + `mobsf/MobSF/settings.py:180,392`
- **Evidence:** Live curl against `192.168.2.118:8001/login/` returns HTTP/200 with `csrftoken` cookie missing the `Secure` flag and no `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, or CSP header. No nginx/caddy on the host (`ss -tlnp` shows only gunicorn on `:8001`). `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')` is set unconditionally despite no proxy — a LAN attacker can send `X-Forwarded-Proto: https` and Django reports `is_secure() == True` over plaintext. `ALLOWED_HOSTS = ['127.0.0.1', 'mobsf', '*']` accepts any Host header. Confirmed by DevOps, Security, NOC, Investor, and Coder; all five teams flagged this independently.
- **Fix:** Add nginx (or caddy) terminating TLS on 443 with an internal CA cert (or LE via DNS challenge), proxy to `127.0.0.1:8001`, rebind gunicorn to `127.0.0.1`. Drop `'*'` from `ALLOWED_HOSTS`, drive from env. Set `SESSION_COOKIE_SECURE=True`, `CSRF_COOKIE_SECURE=True`, `SECURE_HSTS_SECONDS=31536000`, `SECURE_CONTENT_TYPE_NOSNIFF=True`, `X_FRAME_OPTIONS='DENY'` when `DEBUG=False`. Remove `SECURE_PROXY_SSL_HEADER` until the proxy actually exists, then gate behind `MOBINSPECT_BEHIND_PROXY=1`.
- **Effort:** small (the proxy unit) + trivial (the settings)

### C4. Production `MIDDLEWARE` is missing SecurityMiddleware, XFrameOptionsMiddleware, CommonMiddleware, and RatelimitMiddleware
- **Area:** `mobsf/MobSF/settings.py:197-222`
- **Evidence:** Lines 197-207 define a `MIDDLEWARE_CLASSES` tuple (deprecated in Django 1.10, ignored since 2.0). The active `MIDDLEWARE` tuple (208-222) on Django 6.0.3 omits `django.middleware.security.SecurityMiddleware`, `django.middleware.common.CommonMiddleware`, `django.middleware.clickjacking.XFrameOptionsMiddleware`, and `django_ratelimit.middleware.RatelimitMiddleware`. The inline comment at line 211 explicitly acknowledges "was lost in the MIDDLEWARE rename" for WhiteNoise — someone already tripped on this. Live response headers (see C3) confirm none of these middlewares run. Only the login view has an explicit `@ratelimit` decorator; no other endpoint is throttled.
- **Fix:** Delete `MIDDLEWARE_CLASSES` entirely. Add `SecurityMiddleware` (first), `CommonMiddleware`, `XFrameOptionsMiddleware`, and `RatelimitMiddleware` to the active `MIDDLEWARE` tuple. Same diff fixes C3's missing-headers symptom.
- **Effort:** trivial

### C5. SQLite in delete-mode with `busy_timeout=0` deadlocks under any concurrency
- **Area:** `mobsf/MobSF/settings.py:166-171`
- **Evidence:** Live PRAGMA query on production: `journal_mode=delete, synchronous=2 (FULL), busy_timeout=0`. settings.py provides no `OPTIONS` dict. Gunicorn `--workers 1 --threads 10` plus django-q2 (4 worker children) all share the same SQLite file (both ORM writes and Q_CLUSTER broker — `'orm': 'default'`). In delete-mode any writer blocks all readers; with `busy_timeout=0` a second concurrent writer fails immediately with `database is locked`. Confirmed by NOC against live production.
- **Fix:** `DATABASES['default']['OPTIONS'] = {'timeout': 20, 'init_command': 'PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;'}`. One settings change unblocks every other concurrency improvement. Long-term: move Q_CLUSTER broker off SQLite (Redis or Postgres) and consider Postgres for primary storage.
- **Effort:** trivial

### C6. Web service runs scans synchronously; `MOBSF_ASYNC_ANALYSIS=1` is set only on the worker
- **Area:** `deploy/systemd/mobinspect.service` (missing env) + `mobsf/StaticAnalyzer/views/android/apk.py:273`
- **Evidence:** `mobinspect-worker.service:18` sets `MOBSF_ASYNC_ANALYSIS=1` but `mobinspect.service` and its `avd.conf` drop-in do not. `settings.py:366` reads the env on the gunicorn side; unset = synchronous branch in `apk.py:273` / `ipa.py:262`. With `--workers 1 --timeout 3600`, a single large APK scan freezes the entire UI for up to one hour. The django-q cluster is effectively dead weight. The worker unit's own comment (lines 15-17) acknowledges "Both this worker and the main service must set MOBSF_ASYNC_ANALYSIS=1" — the misconfiguration is documented but not implemented.
- **Fix:** Add `Environment=MOBSF_ASYNC_ANALYSIS=1` to `deploy/systemd/mobinspect.service.d/avd.conf` (or a new `async.conf`). Once async is on, bump gunicorn to `--workers 2 --worker-class gthread --threads 4 --max-requests 200 --timeout 180 --graceful-timeout 30`.
- **Effort:** trivial

### C7. Default seeded `mobsf/mobsf` superuser, banner advertises it on every boot, RUNBOOK ships `changeme123`
- **Area:** `mobsf/MobSF/utils.py:122-128`, `setup.sh:51-52`, `scripts/entrypoint.sh:8`, `deploy/RUNBOOK.md:99`
- **Evidence:** Startup banner unconditionally prints `Default Credentials: mobsf/mobsf`. `setup.sh:52` and `scripts/entrypoint.sh:8` actually seed that user via `createsuperuser --noinput` (Dockerfile path). RUNBOOK.md:99 tells operators to set the superadmin password to `changeme123`. No `must_change_password` middleware, no first-login-rotation. Password validator floor is 6 characters (`settings.py:279`). On a LAN-exposed `192.168.2.118:8001` with plaintext HTTP (C3), credential interception or default-cred login is trivial. Confirmed by Investor, Security, DevOps, Founder.
- **Fix:** Remove the `Default Credentials` banner. Replace `setup.sh`/`entrypoint.sh` with a `manage.py bootstrap_admin` that requires `MOBINSPECT_ADMIN_PASSWORD` env (random and written to `~/.MobInspect/initial-admin-password.txt` mode 0600 if unset, printed once into the journal), sets `must_change_password=True`, and refuses to run if a superuser already exists. Bump password min length to 12. Refresh RUNBOOK with the new flow.
- **Effort:** small

---

## High-priority findings (P1)

### H1. `TimeoutStopSec=30` vs gunicorn `--timeout 3600` causes SIGKILL mid-scan
- **Area:** `deploy/systemd/mobinspect.service:19,24`
- **Evidence:** Journal: `2026-05-19 13:08:13 Failed with result 'timeout'` followed by SIGKILL of gunicorn + Java/jadx children. Combined with C6 (sync scans), restart-during-scan corrupts `RecentScansDB.SCAN_LOGS` and leaves half-written upload dirs.
- **Fix:** Raise `TimeoutStopSec` to 600s with `KillSignal=SIGTERM`. Once C6 is in, lower gunicorn `--timeout` to 180s. Add a pre-stop drain hook.
- **Effort:** trivial

### H2. Web service OOM-killed in production; no memory ceiling, no swap
- **Area:** `deploy/systemd/mobinspect.service`
- **Evidence:** Journal: `2026-05-19 13:55:16 mobinspect.service: Failed with result oom-kill`. `free -m` shows `Swap: 0 0 0`. Unit has no `MemoryMax`, `MemoryHigh`, `OOMScoreAdjust`, `TasksMax`, or `LimitNOFILE`. JADX alone can take 2-6 GB; concurrent AVD adds ~2 GB.
- **Fix:** `MemoryHigh=6G MemoryMax=8G TasksMax=4096 LimitNOFILE=16384` on the web unit; `MemoryMax=4G` on worker; `MemoryMax=6G` on AVD. Add 4 GB swap or zswap.
- **Effort:** trivial

### H3. No `/healthz`, `/readyz`, or `/metrics` endpoint
- **Area:** `mobsf/MobSF/urls.py`
- **Evidence:** Only `/status/` exists and it requires `@login_required` + POST + valid MD5. Docker `HEALTHCHECK` hits `host.docker.internal:8000/` (wrong host, wrong port). No `ExecStartPost` curl probe on the systemd unit. `systemctl is-active` returns green for wedged gunicorn. Confirmed by DevOps, NOC, Investor.
- **Fix:** Add unauthenticated `GET /healthz` returning 200 + JSON `{db, queue, adb}` (touch DB with `SELECT 1`, ping qcluster, check `adb devices`). Wire into Dockerfile HEALTHCHECK on `:8001/healthz`, into systemd `ExecStartPost`, and any external uptime monitor. Also add `/metrics` via `django-prometheus`.
- **Effort:** small

### H4. No backup or DR plan for `~/.MobInspect/{db.sqlite3, secret, uploads, signatures}`
- **Area:** Deployment / DR
- **Evidence:** `crontab -l`, `sudo crontab -l`, `systemctl list-timers` on the prod host have no `mob*` entry. No script under `deploy/`. RUNBOOK has no "Backup" or "Disaster recovery" section. SQLite is the single physical file holding audit log, RBAC assignments, API key hashes, and scan history. A `rm -rf ~/.MobInspect` is total loss. Confirmed by DevOps, Investor, NOC, SOC.
- **Fix:** Ship `mobinspect-backup.service` + `.timer` that runs `sqlite3 ~/.MobInspect/db.sqlite3 .backup /var/backups/mobinspect/db-%Y%m%d-%H%M%S.sqlite3` hourly and `restic` to off-host. Document restore in RUNBOOK with RPO≤24h, RTO≤4h. Rehearse quarterly.
- **Effort:** small

### H5. No log rotation for `~/.MobInspect/debug.log`; journald has no retention pinning
- **Area:** `mobsf/MobSF/settings.py:314-326`
- **Evidence:** Plain `logging.FileHandler` at DEBUG for 6 loggers; no `RotatingFileHandler`; no `/etc/logrotate.d/mobinspect` on host; `journalctl --disk-usage` = 288 MB with empty `[Journal]` section in `/etc/systemd/journald.conf`.
- **Fix:** Switch handler to `RotatingFileHandler(maxBytes=50_000_000, backupCount=10)` and drop log level to INFO in prod. Drop `/etc/systemd/journald.conf.d/mobinspect.conf` with `SystemMaxUse=2G`, `MaxRetentionSec=180day`, `ForwardToSyslog=yes`.
- **Effort:** trivial

### H6. Hardcoded systemd unit lacks all sandbox/resource directives; AVD has neither
- **Area:** `deploy/systemd/mobinspect-avd.service` (no `NoNewPrivileges`, no `PrivateTmp`, no `ProtectSystem`)
- **Evidence:** Web and worker units set `NoNewPrivileges=true` + `PrivateTmp=true` only. AVD unit sets none of `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `ReadWritePaths`, `RestrictAddressFamilies`, `SystemCallFilter`. The AVD process runs adversary-controlled APKs with adb root and `-writable-system` — it should be the *most* sandboxed, not the *least*.
- **Fix:** Add `NoNewPrivileges=true PrivateTmp=true ProtectSystem=strict ProtectHome=read-only ProtectKernelTunables=true ProtectControlGroups=true` to mobinspect-avd.service with explicit `ReadWritePaths=/home/ubuntu/.android /home/ubuntu/.MobInspect/avd-runtime` and `DeviceAllow=/dev/kvm rw`. Add the same baseline to web/worker plus `MemoryMax` / `CPUQuota` (see H2).
- **Effort:** small

### H7. Login success / failure / logout / user-create / user-delete / password-change are NOT audited
- **Area:** `mobsf/MobSF/views/authentication.py:49-91`, `mobsf/MobSF/views/authorization.py:146-210`
- **Evidence:** Grep `audit.record` in `mobsf/MobSF/` returns 0 hits. `user_logged_in`/`user_login_failed`/`user_logged_out` signal receivers don't exist anywhere. Only the `/login` route has `@ratelimit(7/m)` for friction; failures are silently re-rendered. SOC has zero forensic trail for the most basic identity events.
- **Fix:** Wire Django auth signals in `mobsf/RBAC/signals.py`, call `audit.record(request, 'auth.login.ok|fail|logout', metadata={'username': ...})`. Wrap `create_user`, `delete_user`, `change_password` in `audit.record(...)` with target_type='user'. Same pattern for scan upload/delete/rescan/PDF-export and Frida script upload (currently no audits for any of these despite catalog codenames existing).
- **Effort:** small

### H8. API authentication failures are not audited or rate-limited
- **Area:** `mobsf/MobSF/views/api/api_middleware.py:95-102`
- **Evidence:** `process_request` returns bare 401 on auth failure with no logging, no audit, no rate limit. `api_auth()` doesn't audit successful key use either. The only `@ratelimit` in the project is on `login_view`. An attacker can iterate API keys at full gunicorn throughput.
- **Fix:** On failure, `audit.record(request, 'api.auth.fail', metadata={'prefix': presented[:11], 'path': request.path})`. Add per-IP and per-key rate limiting via `@ratelimit` on api_middleware or the api urlconf (60/m default). Enforce `api.use` permission in `api_auth` after resolving the user (currently the codename exists but is never checked).
- **Effort:** small

### H9. Audit log is append-only by *convention* only
- **Area:** `mobsf/RBAC/models.py:126-147`
- **Evidence:** AuditEvent model is ordinary Django, no `save()` override, no `pre_save`/`pre_delete` receiver, no SQLite trigger, no `prev_hash` field, no HMAC. The on-disk SQLite is the sole copy (no SIEM forwarder). A compromised admin can `AuditEvent.objects.all().delete()` and the only event that would record it isn't recorded.
- **Fix:** Add `prev_hash` SHA-256 over `(prev_hash + actor_id + action + target_type + target_id + metadata_json + occurred_at)`, computed on save. Add SQLite trigger `CREATE TRIGGER no_audit_modify BEFORE UPDATE OR DELETE ON RBAC_auditevent BEGIN SELECT RAISE(ABORT,'audit immutable'); END;`. Pair with H10 so on-disk DB is not the sole copy.
- **Effort:** medium

### H10. No SIEM/syslog/JSON-lines audit exporter; AuditEvent is single-copy in SQLite
- **Area:** Observability / audit
- **Evidence:** Grep over the entire repo for `syslog|splunk|loki|graylog|fluent|logstash|elastic` returns zero integration hits. `audit_log.html` has Filter/Reset/Prev/Next but no Export button. No `manage.py audit_export` command. SOC can only review via the in-app paginated UI.
- **Fix:** Add a `mobinspect_audit` Python logger handler that emits each AuditEvent as one JSON line to stdout (picked up by journald → ForwardToSyslog → external rsyslog/Loki). Add `manage.py audit_export --since DATE --format jsonl`. Add an "Export CSV/JSONL" button on `/rbac/audit/` gated by a new `audit.export` permission.
- **Effort:** medium

### H11. No failed-login lockout; only a soft 7/min rate limit on `/login`
- **Area:** Authentication brute-force defense
- **Evidence:** No `django-axes` in `pyproject.toml`. `@ratelimit(rate='7/m', block=True)` returns 403 but does not lock the account, audit the event, or notify anyone. Distributed attackers rotating IPs are not throttled.
- **Fix:** Add `django-axes` (or roll equivalent) keyed on username+IP with lockout after 5 failures, exponential cooldown, and an `account.locked` audit event. Add a periodic django-q job that scans for `denied`/`auth.login.fail` spikes and POSTs to a configurable webhook.
- **Effort:** medium

### H12. Frida server downloaded at scan time over public internet with no SHA256 verification
- **Area:** `mobsf/DynamicAnalyzer/views/common/frida/server_update.py:81-128`
- **Evidence:** First scan after a Frida version bump hits `api.github.com`, parses release JSON, streams `.xz` through `LZMAFile`, pushes the binary to `/system/fd_server` with `chmod 755` and runs it as root. No hash check. Failure surfaces only in `mobsf_frida_out.txt`. Air-gapped deployments silently fail.
- **Fix:** Pre-bake frida-server binaries per architecture into `deploy/binaries/`, pin SHA256 per arch in `settings.py`, fail loud on mismatch. Surface download failure as a UI error not a swallowed log line. Pin `frida = "~17.8"` in pyproject to match the frida-tools 14.x constraint.
- **Effort:** medium

### H13. Frida `spawn()` recurses infinitely on `ServerNotRunningError`
- **Area:** `mobsf/DynamicAnalyzer/views/android/frida_core.py:145-173`
- **Evidence:** `except frida.ServerNotRunningError: ... self.spawn()` — no attempt counter, no backoff. If `/system/fd_server` is missing or fails to start (silently caught by `adb_command()`), every retry adds a stack frame and a 2-3s sleep until the worker thread dies. Same pattern in `session()` at line 202-205.
- **Fix:** Bounded retry with exponential backoff (max 3 attempts), verify `fd_server` is actually listening via `adb shell ps | grep fd_server` before recursing, emit a structured `frida_log` message the UI can render.
- **Effort:** small

### H14. AVD bootstrap (`adb root` + `disable-verity` + `remount`) is a manual one-time ritual with no enforcement
- **Area:** Deployment / AVD lifecycle
- **Evidence:** RUNBOOK.md:42-53 documents the bootstrap as a manual procedure. The systemd unit has no `ExecStartPre` hook. `system_check()` only catches the symptom (`b'Read-only'` from a `touch /system/test`) at scan time, after `connect_n_mount` already returned a misleading "Cannot Connect" error.
- **Fix:** Ship `deploy/scripts/avd-bootstrap.sh` that idempotently runs root/disable-verity/reboot/remount and verifies `getprop sys.boot_completed`. Wire as `ExecStartPre=` on the AVD unit or as a separate one-shot `mobinspect-avd-bootstrap.service` ordered `Before=`. Add `ExecStartPost=/bin/bash -c 'until adb -s emulator-5554 shell getprop sys.boot_completed | grep -q 1; do sleep 2; done'` for readiness.
- **Effort:** small

### H15. Single-device hardcoding + module-global `_FPID`/`ADB_PATH` races on concurrent scans
- **Area:** `mobsf/DynamicAnalyzer/views/android/frida_core.py:27`, `mobsf/MobSF/utils.py:445-468`
- **Evidence:** `ANALYZER_IDENTIFIER=emulator-5554` is pinned in `avd.conf:11`. `_FPID` is a module global in `frida_core.py`. `get_adb()` sets `os.environ['MOBSF_ADB']` as a side effect in a finally block, which `dynamic_analyzer.py:286 logcat()` then reads. Under `--threads 10`, two concurrent scans race on the global PID and share emulator state.
- **Fix:** Replace `os.environ['MOBSF_ADB']` reads with `get_adb()` calls; drop the env side-effect in `get_adb()`. Add a per-process lock + queue for dynamic-analysis sessions, OR formally document and serialize dynamic via a single-worker django-q task.
- **Effort:** medium

### H16. Audit log captures `X-Forwarded-For` without trusted-proxy verification
- **Area:** `mobsf/RBAC/audit.py:43-50`
- **Evidence:** `_client_ip` unconditionally takes the first comma-separated `X-Forwarded-For` value. No reverse proxy in production. Any LAN client can spoof `X-Forwarded-For: 1.2.3.4` to corrupt `AuditEvent.ip_address`. Same pattern would apply to any future IP-based rate limit.
- **Fix:** Honor `X-Forwarded-For` only when `REMOTE_ADDR` is in a configured `MOBINSPECT_TRUSTED_PROXY_CIDRS` env list; otherwise log `REMOTE_ADDR`.
- **Effort:** trivial

### H17. Zero tests for RBAC, Analytics, env shim, API middleware
- **Area:** `mobsf/RBAC/`, `mobsf/Analytics/`
- **Evidence:** `find mobsf/{RBAC,Analytics} -name 'test*.py'` returns nothing. `mobsf/DynamicAnalyzer/tests.py` and `mobsf/MalwareAnalyzer/tests.py` are 0 bytes. The privilege-escalation guard at RBAC/views.py:171-184, ApiKey atomic lookup at models.py:204-223, signals.py mirror, and analytics aggregations all ship with zero automated coverage. Independently raised by Coder, Investor, Code Auditor, Founder.
- **Fix:** Add `mobsf/RBAC/tests/` with: `test_permissions.py` (effective_user, superuser fast-path, expired assignment), `test_api_key.py` (generate/lookup/revoke/expiry, collision-free), `test_signals.py` (group membership mirror), `test_views_escalation.py` (cannot grant role with perms you don't hold), `test_decorators.py` (allow/deny/anonymous/api/dev-bypass). Target ~70% coverage on RBAC. Add a smoke test for Analytics dashboard. Wire into tox + Gitea Actions CI.
- **Effort:** medium

### H18. PDF reports and in-app logo still ship as `mobsf_logo.png` / `mobsf_icon.png`
- **Area:** `mobsf/templates/pdf/{android,ios,windows}_report.html` + `mobsf/templates/base/base_layout.html`
- **Evidence:** All four references verified. Every PDF an analyst exports — the single most-shared artifact — visibly says "MobSF". The wordmark text `<strong> Mob</strong>SF` is also still in `base_layout.html:53`. Only one MobInspect asset exists (`mobsf/static/mobinspect/img/favicon.svg`).
- **Fix:** Commission a real MobInspect wordmark, drop into `mobsf/static/mobinspect/img/`, swap the four references plus the literal text in `base_layout.html`.
- **Effort:** small (asset + 5 edits)

### H19. Scan reports and entire dynamic-analyzer UI still render in legacy AdminLTE
- **Area:** `mobsf/templates/` (~16 files extending `base/legacy_app.html` or `base/base_layout.html`)
- **Evidence:** Static binary/source analysis templates use new `base/app.html` but their content is full of Bootstrap-4 `card-body`, FontAwesome `fab fa-android`, `data-toggle="collapse"`. Every Android/iOS dynamic analyzer template (dynamic_analyzer.html, dynamic_report.html, frida_logs.html, live_api.html, logcat.html) extends `legacy_app.html`. `mobsf/static/adminlte/` is 6.6 MB shipped alongside Tailwind.
- **Fix:** Phase 2.2/2.3 burn-down: migrate the 16 templates to Tailwind/`base/app.html`. Delete `mobsf/static/adminlte/` once orphaned. Until then, never demo past the home + scans list + AppSec scorecard.
- **Effort:** large

### H20. SECURITY.md / SUPPORT.md / update-check / pyproject all point at upstream MobSF
- **Area:** `.github/SECURITY.md`, `.github/SUPPORT.md`, `mobsf/MobSF/settings.py:137`, `pyproject.toml:9,10,20`
- **Evidence:** `SECURITY.md` routes vuln reports to upstream MobSF advisories. `SUPPORT.md` links MobSF Slack. `GITHUB_URL` in settings is upstream; `check_update` runs at startup, fetches upstream version, and emits `"A new version of MobInspect is available, Please update to %s from master branch"` with the upstream version number. `pyproject.toml` `repository`, `documentation`, `Bug Tracker` all point at MobSF GitHub. Per-user API auth header is `X-Mobsf-Api-Key` with no `X-MobInspect-Api-Key` alias.
- **Fix:** Rewrite SECURITY.md and SUPPORT.md with `security@appdirs.in` and the Gitea PR URL. Repoint `GITHUB_URL` to `gitea.appdirs.in/Appdirs/Mobins/releases/latest` (or add `MOBINSPECT_DISABLE_UPDATE_CHECK=1`). Repoint pyproject URLs. Accept both `X-MobInspect-Api-Key` and `X-Mobsf-Api-Key` headers (12-month deprecation).
- **Effort:** small

### H21. ANDROID_API_SUPPORTED=30 caps dynamic analysis at a 4-year-old Android
- **Area:** `mobsf/DynamicAnalyzer/views/android/environment.py:40`
- **Evidence:** Hard ceiling at API 30 (Android 11, Sep 2020). `system_check()` rejects API 31+. Play Store mandates `targetSdk >= 34` for new submissions; a growing share of customer apps target Android 14/15. `connect_n_mount` returns False with no propagated reason, surfacing as misleading "Cannot Connect to <identifier>".
- **Fix (engineering):** Investigate Magisk-on-AVD or `adb root` + bind-mount overlay for newer APIs; pivot to Corellium (already integrated) for newer APIs; install CA into `/apex/com.android.conscrypt/cacerts/` and `/data/misc/keychain/cacerts-added/<hash>.0`.
- **Fix (immediate):** Surface the actual API-mismatch error to the UI instead of "Cannot Connect". Document the ceiling as a product limitation in README / sales material.
- **Effort:** large (real fix) / trivial (better error)

### H22. README clone/wiki URLs are private RFC1918 (192.168.3.244); external users cannot install
- **Area:** `README.md:77,94,135,159,191-194`
- **Evidence:** Six lines point at `http://192.168.3.244:3000/Appdirs/Mobins/...` — an internal LAN address. Even the `git clone` URL is unreachable from outside Appdirs. README also says AVD is "Pixel 6 / Android 13" while code+RUNBOOK require Pixel 4 / API 30.
- **Fix:** Host clone+wiki at a public domain (gitea.appdirs.in) OR inline install/troubleshooting into `docs/` and reference as relative paths. Fix the Pixel 6/Android 13 reference to Pixel 4/Android 11/API 30 everywhere.
- **Effort:** small

### H23. `init.py:143` calls non-existent `create_roles` management command
- **Area:** `mobsf/MobSF/init.py:143`, `mobsf/MobSF/__main__.py:28`, `.github/workflows/mobsf-test.yml:71`
- **Evidence:** Code invokes `django_operation(['create_roles'], base_dir)` but the only registered command is `seed_rbac`. Any code path that hits `init.migrate()` (the `mobsf db` / `mobinspect db` entrypoint) raises `CommandError`.
- **Fix:** Rename `seed_rbac` → `create_roles` (one git mv) or update the three call sites. Add a tiny CI smoke test: `manage.py migrate --check && manage.py create_roles`.
- **Effort:** trivial

### H24. `scripts/clean.sh` deletes the just-shipped StaticAnalyzer migrations
- **Area:** `scripts/clean.sh:31`
- **Evidence:** `rm -rf ./mobsf/{...,StaticAnalyzer/migrations,...}/*`. The recent fix-fresh-deploy commit un-gitignored `StaticAnalyzer/migrations/0001_initial.py`; any developer running `clean.sh` wipes the file and the next `migrate` fails with `no such table`.
- **Fix:** Remove `StaticAnalyzer/migrations` from the cleanup target list. Add a warning if any tracked migration files would be deleted. Also remove `*/migrations/*` from `.gitignore:69` so the next Appdirs-added app doesn't recreate the same bug.
- **Effort:** trivial

### H25. RBAC permission catalog is theatre — ~25 of 30 seeded permissions are never enforced
- **Area:** `mobsf/RBAC/migrations/0002_seed_permissions.py` vs `@require_permission` usage
- **Evidence:** Migration seeds ~30 codenames. Only 5 are referenced by `@require_permission`: `analytics.view`, `audit.view`, `api.key.create`, `rbac.role.view`, `rbac.role.manage`. The legacy mirror in `signals.py:78-85` translates 3 more (`scan.create`, `scan.delete`, `finding.suppress`) into Django Group permissions for the still-active `permission_required(Permissions.X)` decorators on scan/dynamic views. `admin.user.create/delete` is gated by `@staff_member_required`, not the codename. The remaining ~14 (`analytics.export`, `dynamic.frida.script`, `integration.virustotal.upload`, etc.) confer nothing — operators see a granular catalog in the UI that doesn't gate anything.
- **Fix:** Either (a) finish wiring `@require_permission` onto the actual scan/dynamic/finding/integration views and retire `Permissions` enum + signals mirror, or (b) prune the seeded catalog to what's enforced. Document the state in `docs/03-rbac-design.md` until fixed.
- **Effort:** large (full migration) or small (catalog prune)

### H26. Two parallel auth systems with no deprecation plan
- **Area:** `mobsf/MobSF/views/authorization.py` vs `mobsf/RBAC/`
- **Evidence:** Two `has_permission` functions in different modules with different signatures. Legacy `permission_required(Permissions.SCAN)` is still applied to the dynamic and static analyzer views; new `@require_permission` is only on RBAC + Analytics. `RegisterForm` still creates Django Groups directly. `signals.py` mirrors 3-of-30 codenames between systems. Adding a new permission requires updating both systems.
- **Fix:** Pick the new RBAC and write a deprecation plan with a date (e.g. end of Q3). Replace every legacy `permission_required(Permissions.X)` call site with `@require_permission('scan.create' | ...)`. Delete `Permissions` enum + `can_scan/can_suppress/can_delete` + the signals mirror.
- **Effort:** large

### H27. CORS `Access-Control-Allow-Origin: *` on every API response
- **Area:** `mobsf/MobSF/views/api/api_middleware.py:20-22, 98-99`
- **Evidence:** Every API JSON response and the OPTIONS preflight return `*` with `Allow-Headers: Authorization, X-Mobsf-Api-Key`. Mitigated only by header-based auth (no `Allow-Credentials`), but unauthenticated OPTIONS reveals the API surface to any origin.
- **Fix:** Replace `*` with a `MOBINSPECT_CORS_ORIGINS` allowlist (default empty for a tool of this sensitivity). Require auth on OPTIONS unless absolutely needed.
- **Effort:** trivial

### H28. No reverse-proxy / no firewall ruleset shipped; ports 8001/5037/5554/5555/1337 reachable from any LAN host
- **Area:** Network posture
- **Evidence:** `ss -tlnp` shows gunicorn on `0.0.0.0:8001`, `adb` on `127.0.0.1:5037/5554/5555`, mitmproxy on `1337`. `ufw` inactive on Ubuntu default. No firewall config in `deploy/`. RUNBOOK doesn't mention firewall posture.
- **Fix:** Ship `deploy/firewall/ufw.rules` allowing 22/tcp from mgmt range + 443/tcp from analyst range; block 8001/5037/5554/5555/1337 from non-localhost. Add to RUNBOOK as required.
- **Effort:** trivial

### H29. Repo ships dual deployment tracks: upstream Docker + new systemd, with conflicting defaults
- **Area:** `Dockerfile`, `docker/docker-compose.yml`, `.github/workflows/docker-*.yml`
- **Evidence:** Dockerfile exposes 8000, sets `mobsf/mobsf` superuser, adb at `/usr/bin/adb`. Systemd binds 8001, drop-in sets adb at `/home/ubuntu/android-sdk/platform-tools/adb`. docker-compose hardcodes `POSTGRES_PASSWORD=password`, runs nginx 80→4000. CI workflows publish to `opensecurity/mobile-security-framework-mobsf` Docker Hub (upstream namespace) on every master push.
- **Fix:** Pick one. Either delete `Dockerfile`, `docker/`, `.dockerignore`, `docker-*.yml`, and `python-publish.yml`; OR rewrite Dockerfile to mirror the systemd unit (port 8001, no default password, healthcheck `/healthz`) and add `docker/README.md` clarifying scope. Either way, gate the workflows on `if: github.repository == 'MobSF/...'` so they can't accidentally fire.
- **Effort:** medium

### H30. No CI on the `mobinspect` branch — every push is untested
- **Area:** `.github/workflows/` (GitHub Actions) vs Gitea hosting
- **Evidence:** Repo lives on Gitea at `192.168.3.244:3000`. `.github/workflows/mobsf-test.yml` triggers `on: branches: [master]` and never runs against `mobinspect`. No `.gitea/workflows/` directory.
- **Fix:** Port to `.gitea/workflows/test.yml` (Forgejo/Gitea Actions are Actions-compatible since 1.19), or a server-side post-receive hook running `tox -e lint test`. At minimum, run flake8 + the RBAC/Analytics test suite (H17) on every push.
- **Effort:** small

### H31. Half-finished rebrand: 80 `MOBSF_*` env vars in `settings.py`, only 5 routed through the env() shim
- **Area:** `mobsf/MobSF/init.py:23-51` + `mobsf/MobSF/settings.py`
- **Evidence:** `env()` shim in init.py supports `MOBINSPECT_*` with `MOBSF_*` fallback and a DeprecationWarning. Used for exactly 4 distinct settings (SECRET_KEY, HOME_DIR, API_KEY_FILE, API_KEY). The other 80 settings call `os.getenv('MOBSF_...')` directly. Operators setting `MOBINSPECT_VT_API_KEY` silently get no VirusTotal integration.
- **Fix:** Route every `os.getenv` in settings.py through `env('MOBINSPECT_X', 'MOBSF_X', default=...)`. Add a CI test that asserts both forms resolve identically. Same shim handles the deprecation warning automatically.
- **Effort:** medium

### H32. Founder/commercial gaps: no marketing site, no pricing, no contact email, no public demo, no SARIF/JUnit export, no OIDC, no webhooks
- **Area:** Commercial readiness
- **Evidence:** Repo-wide grep for `pricing|landing|contact@appdirs|support@appdirs` returns no marketing content. `templates/general/about.html:39` advertises "CI/CD security gating via REST API" but the API has only proprietary JSON output. `pyproject.toml` has `python3-saml` but no `mozilla-django-oidc`. No `webhook` model anywhere in `mobsf/`.
- **Fix:** Stand up `mobins.appdirs.in` landing page (pricing, demo video, contact, hosted demo). Decide GPL-3.0 commercial-license posture with outside counsel. Add `format=sarif`/`format=junit` to `/api/v1/scorecard` and `/api/v1/report_json` (mechanical transforms over the existing scorecard dict). Add OIDC via `mozilla-django-oidc` (~200 LoC, mirroring the SAML group→role map). Ship a `Webhook` model + django-q hook for `scan.completed` / `finding.critical_added` JSON POSTs.
- **Effort:** large (commercial track), medium (technical features)

### H33. GPL-3.0 monetization paths unaddressed
- **Area:** `LICENSE.md`, `pyproject.toml:7`
- **Evidence:** Inherited GPL-3.0; strong-copyleft. SaaS-only is technically permitted (GPLv3 doesn't close network use); on-prem appliance / closed plugin marketplace / OEM embedding is foreclosed without dual-licensing or rewrite. Upstream contributor Ajin Abraham holds ~1210 commits, Vipin 20 — Appdirs cannot unilaterally relicense. Confirmed by Investor and Founder.
- **Fix:** Commission an outside IP-law memo. Decide explicitly: (a) SaaS-only positioning, (b) negotiate commercial relicense from upstream, or (c) wrap unmodified MobSF with a permissive-licensed differentiation layer. Without this, every monetization conversation stalls on legal diligence.
- **Effort:** small (memo), policy decision

---

## Gaps — what's missing

### Security
- **Reverse proxy + TLS** (DevOps, Security, NOC, Investor) — P0
- **Account lockout / brute-force protection** (Security, SOC) — P0
- **Tamper-evident audit log** (hash chain + DB trigger preventing UPDATE/DELETE) (SOC) — P1
- **SIEM/syslog/JSON-lines audit forwarder** (SOC) — P0
- **MFA for admin accounts** (Security) — P2
- **Standard Django security headers** (HSTS, CSP, Referrer-Policy, SameSite, HttpOnly, Secure cookies) (Security, DevOps) — P1
- **Trusted-proxy / IP-source policy** for X-Forwarded-For (SOC, Security, Code Auditor) — P2
- **Secret scanning + dependency CVE scanning in CI** (Security) — P2
- **MFA / hardware key / SSO break-glass procedure** (SOC) — P3

### Operations / NOC
- **`/healthz`, `/readyz`, `/metrics` endpoints** (DevOps, NOC, Investor) — P0
- **Backup + restore plan for `~/.MobInspect`** (DevOps, NOC, Investor, SOC) — P0
- **Log rotation for `debug.log` + journald retention pin** (DevOps, NOC, SOC) — P1
- **Memory ceiling + swap on host** (NOC) — P1
- **External uptime probe + on-call rotation** (NOC, DevOps) — P1
- **Documented capacity model** (NOC) — P2
- **Internal DNS name for host** (NOC) — P2
- **PostgreSQL deployed (code path exists, unused)** (NOC, Investor) — P1
- **Multi-emulator / ANDROID_ADB_SERVER_ADDRESS plumbing** (NOC, Android) — P2

### Product / Commercial
- **Public marketing site / landing / pricing / contact** (Founder, Investor) — P0
- **Commercial license decision and dual-track for SaaS / closed-source resale** (Founder, Investor) — P0
- **SARIF / JUnit / CycloneDX export** (Founder) — P0
- **OIDC SSO** (Founder) — P1
- **Webhook / Slack / Teams / email notifications** (Founder, SOC) — P1
- **Compliance-mapped reports (OWASP MASVS, NIST 800-53, PCI DSS, HIPAA)** (Founder) — P1
- **Public hosted demo with seeded findings** (Founder) — P1
- **`security@appdirs` email + SLA** (Founder, Investor, SOC) — P1
- **CI/CD recipe library** (GitHub Actions, GitLab, Jenkins) (Founder) — P2
- **Customer-visible CHANGELOG / release notes feed** (Founder) — P2
- **Upgrade-path docs from MobSF → MobInspect** (Founder) — P2

### Engineering / Quality
- **Tests for RBAC, Analytics, env shim, API middleware, signals** (Coder, Investor, Code Auditor, Founder) — P0
- **CI on the Gitea `mobinspect` branch** (Code Auditor, Investor, Coder) — P0
- **Type hints in RBAC/Analytics** (Coder) — P2
- **Linter+formatter in CI** (Coder) — P1
- **Migration `--check` + `seed_rbac` smoke test in CI** (Coder) — P1
- **Pinned upper bounds on Django, gunicorn, frida** (Coder, Android) — P2
- **Documented permission catalog → view-decorator audit** (Coder, Code Auditor) — P1
- **Rate-limiting on API key creation, role mutation, audit-log filter** (Coder, Security) — P2
- **`lxml` as explicit dependency in pyproject** (Code Auditor) — P2
- **CHANGELOG.md tracking fork divergence** (Code Auditor) — P2

### Android / Dynamic
- **Path off ANDROID_API_SUPPORTED=30** (Android) — P0
- **Idempotent AVD bootstrap script in repo** (Android) — P1
- **Bundled frida-server binaries with SHA256 verification** (Android) — P1
- **Automated AVD readiness probe** (Android, NOC) — P1
- **Queue/lock around dynamic-analysis sessions** (Android, NOC) — P1
- **BoringSSL/Cronet/Flutter/RN-pinning coverage in TLS bypass** (Android) — P1
- **Structured progress for mobsfy_init pipeline in UI** (Android) — P2
- **Headless GL driver verification** (Android) — P3

### Investor / Diligence
- **Business plan, financial model, customer list, pricing** (Investor, Founder) — P0
- **Legal memo on GPL-3.0 monetization paths** (Investor, Founder) — P0
- **Second engineer / bus factor > 1** (Investor) — P1
- **Documented competitive analysis** (Investor, Founder) — P1
- **SOC 2 / ISO 27001 / HIPAA controls documentation** (Investor) — P1
- **DR runbook with RPO/RTO** (Investor, DevOps, NOC) — P1
- **CONTRIBUTING.md for the Appdirs fork** (Investor) — P2

### SOC / Compliance
- **Authentication audit coverage (login/logout/password change)** (SOC) — P0
- **User lifecycle audit (create/delete/staff-toggle)** (SOC) — P0
- **Scan upload/delete/rescan/export audit** (SOC) — P1
- **Frida script upload audit** (SOC) — P1
- **GDPR right-to-erasure procedure + retention policy** (SOC) — P1
- **Threat model document** (SOC, Investor) — P1
- **Incident response runbook** (SOC, Investor) — P1
- **Audit log time-range filtering + export** (SOC) — P2

---

## Broken flows

| # | Flow | Symptom | Fix |
|---|---|---|---|
| 1 | API-key holder with Viewer role calls `/api/v1/android/adb_command` | Returns 200 and executes arbitrary adb shell. RBAC role is irrelevant. | C1 (remove `if api:` short-circuit + apply `@require_permission`) + C2 (validate `cmd`). |
| 2 | Two analysts upload scans concurrently | Second user blocks (or 502s after 3600s) on the single gunicorn worker; if it gets in, second commit fails with `database is locked`. | C5 (WAL+busy_timeout) + C6 (async on web). |
| 3 | `systemctl restart mobinspect.service` during an active scan | systemd waits 30s, then SIGKILLs gunicorn + jadx + java. Scan left half-written in `uploads/<md5>/`; next view of the scan shows garbled state. | H1 (raise `TimeoutStopSec`, lower gunicorn timeout once async is on). |
| 4 | External monitoring tries to health-check the box | No `/healthz`. Probes hit `/login/` (302 redirect) which 200s even when DB is locked or AVD is offline. False-green monitoring. | H3 (`/healthz` endpoint). |
| 5 | First-time external buyer follows README to install | README links point at `192.168.3.244` (RFC1918). `git clone` fails. Wiki unreachable. | H22 (public domain or inline docs). |
| 6 | Operator runs `./scripts/clean.sh y` | Wipes `mobsf/StaticAnalyzer/migrations/`, including the just-shipped `0001_initial.py`. Next `migrate` fails. | H24 (remove migrations from cleanup target). |
| 7 | Operator runs `mobinspect db` on a fresh install | `init.migrate()` calls `django_operation(['create_roles'], ...)`; only `seed_rbac` exists. `CommandError`. | H23 (rename `seed_rbac` → `create_roles` or update 3 call sites). |
| 8 | Analyst opens a scan report after the new home page | Home is Tailwind; report opens to legacy AdminLTE Bootstrap-4 cards + FontAwesome. "UI is half-done" impression. | H19 (Phase 2.2/2.3 burn-down). |
| 9 | Analyst exports a scan PDF and shares with customer | PDF cover/footer show `mobsf_logo.png` — upstream MobSF wordmark. | H18 (commission and swap in MobInspect wordmark). |
| 10 | Admin creates first analyst user via UI | Form only offers legacy Viewer/Maintainer Django groups; new RBAC roles require a separate Users-page trip. | Replace dropdown with full Role list and create `RoleAssignment` in `create_user`. (Founder finding.) |
| 11 | Security researcher finds a vuln in Appdirs code | `.github/SECURITY.md` directs to upstream MobSF advisories; Appdirs never finds out. | H20 (rewrite SECURITY.md). |
| 12 | Customer wires MobInspect into CI/CD pipeline | API returns proprietary JSON only; no SARIF, no JUnit. Custom transformer required. | H32 (add `format=sarif|junit` to scorecard/report_json). |
| 13 | Existing MobSF user upgrades to MobInspect | `init.py` falls back to `~/.MobSF/` if it exists; user keeps writing to old home with new product name. Confusing on disk. | First-run banner + symlink-or-copy migration. (Founder finding.) |
| 14 | Audit log review for SOC2/compliance | Login/logout/user-create/delete/password-change events don't appear in the audit log. | H7 (wire Django auth signals + audit.record). |
| 15 | Honoring a customer right-to-erasure request | No `manage.py user_erase`. `delete_user` calls `u.delete()`; `AuditEvent.actor` cascades to NULL (orphans); uploads remain; ApiKey rows lose key_hash trail. | Add documented erase command (per SOC). |
| 16 | Operator clicks "Prepare Runtime" when AVD is offline | UI shows cryptic "argument should be a str ... not NoneType" or hangs. No auto-recovery. | H3 (`/healthz` with adb check) + H14 (AVD readiness probe). |
| 17 | Operator recreates the AVD after a wedge | RUNBOOK says delete+recreate but not "re-run disable-verity". Next scan fails system_check with misleading "Cannot Connect". | H14 (idempotent avd-bootstrap.sh that always runs). |
| 18 | Customer analyzes an Android 13/14/15 app | `ANDROID_API_SUPPORTED=30` rejects modern AVD images. Forced to 4-year-old emulator. App may not run cleanly → non-representative results. | H21 (lift ceiling or surface limitation honestly). |
| 19 | Frida script upload from analyst | No audit event recorded despite `dynamic.frida.script` being a `is_dangerous=True` permission in the catalog. | H7 extension (audit Frida uploads). |
| 20 | Host disk failure or `rm -rf ~/.MobInspect/` | Total loss of audit log, RBAC, API keys, scan history. No backup. | H4 (nightly backup + DR runbook). |
| 21 | Long-running APK upload from slow client | WhiteNoise caches static assets for only 60s (no manifest). Every page nav re-fetches CSS/JS through the same gunicorn worker stuck on upload. Effective concurrency drops to single-digit RPS. | `collectstatic` + `CompressedManifestStaticFilesStorage` so hashed assets cache 1 year. (NOC finding.) |
| 22 | Operator enables MOBSF_DEBUG=1 to investigate prod | Full Django tracebacks with SECRET_KEY-derived state visible to any LAN visitor (because `ALLOWED_HOSTS=['*']`). One env var = info leak. | Refuse to boot with `MOBSF_DEBUG=1` unless `MOBINSPECT_DEV=1` is also set. Remove the suggestion from the systemd unit comment. (DevOps finding.) |

---

## What was refuted

For transparency, the adversarial verifier refuted or significantly down-weighted these claims. None of the refuted issues are in the action plan.

| Team | Original claim | Verdict | Reasoning |
|---|---|---|---|
| Coder | "API key creation with expiry crashes — `timezone.timedelta does not exist`" (critical) | **Refuted** | Django's `django.utils.timezone` does re-export `timedelta` (verified: `from datetime import UTC, datetime, timedelta, timezone, tzinfo` in Django 6.0.3's `utils/timezone.py`). Calling `timezone.timedelta(days=7)` returns a valid value. The form does not crash. The stylistic cleanup (use `from datetime import timedelta` to avoid relying on a re-export) is still reasonable, but there is no exploitable bug. |
| Coder | "SessionAuthenticationMiddleware reference will break on a clean install" (high) | **Partial → low** | The reference exists at settings.py:203 but it's inside the dead `MIDDLEWARE_CLASSES` tuple, which Django 6 ignores. The app boots fine today. The risk is latent (if a future maintainer copies the entry into the active `MIDDLEWARE`), so it's a cleanliness issue, not high severity. |
| Coder | "Permission decorators bypass the RBAC middleware cache" (high) | **Partial → low** | Confirmed factually — decorators don't read `request.mi_permissions`, they re-query. But both paths return identical results — no auth bypass, no privilege escalation. Pure performance/cleanliness, not security. |
| Coder | "delete_user uses Python-2 `.message` attribute" (high) | **Confirmed → low** | Real bug, but the route is `@staff_member_required` and the impact is a degraded error path (500 instead of JSON), not auth bypass or info disclosure. Robustness issue, not high-severity security. |
| Coder | "first_run crashes with `'…' % path`" (high) | **Confirmed → medium** | Real bug on a narrow first-run-with-unwritable-secret-dir path. Diagnostics quality, not runtime correctness or security. |
| Code Auditor | "Two `has_permission` functions — namespace collision" (high) | **Partial → low** | Functions are in different modules; Python's import machinery disambiguates. No actual namespace collision. The "silent allow/deny" risk isn't supported by the signatures: RBAC version called with a Permissions Enum returns False (fail-closed); legacy version called with two args raises TypeError. Maintenance hygiene, not security. |
| Code Auditor | "Dead Django settings ... will break on Django 6" (high) | **Partial → low** | Settings exist as cited but they're silently ignored (no runtime/security impact). `TEMPLATE_DEBUG` is actually still used as a local variable at line 240. Code hygiene, not high severity. |
| Security | "ALLOWED_HOSTS = '*' allows Host-header attacks" (high) | **Confirmed → medium** | Bug is real. But there's no password-reset email flow, no OAuth redirect builder, no Django CACHES configured, no `cache_page`/`build_absolute_uri` reflective email. The only live `request.get_host()` consumers are the SAML SP (only relevant if SAML is enabled) and the post-login `next` redirect (mitigated by `url_has_allowed_host_and_scheme` though tautological under `*`). Hardening is still right; severity downgrade is appropriate. |
| Security | "SECURE_PROXY_SSL_HEADER trusts X-Forwarded-Proto" (high) | **Confirmed → medium** | Bug is real. But no `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` / `SECURE_SSL_REDIRECT` is currently set, so today there's no Secure-flagged cookie to leak. The latent risk only materializes once C3 hardening is applied without removing the unconditional SECURE_PROXY_SSL_HEADER. Fix C3 and this in the same change. |
| Security | "CORS `Access-Control-Allow-Origin: *`" (high) | **Partial → medium** | `Access-Control-Allow-Credentials` is never set anywhere, and API auth requires a custom header (not cookies), so cross-origin browsers won't auto-attach credentials. The real residual risks are unauthenticated OPTIONS reconnaissance and a latent foot-gun if `Allow-Credentials` is ever added. Medium fits better than high. |
| Security | "Default ALLOWED_HOSTS wildcard + hardcoded SAML IDP_X509CERT acceptance" (high) | **Partial → medium** | Code is as described, but exploitation requires SAML to actually be enabled (env vars set), a non-normalizing proxy in front, and a permissive IdP. The "silent fallback" framing is partly inverted: the static IDP_X509CERT is operator-supplied, not attacker-influenced. Hardening is still correct but high is overstated. |
| SOC | "Login success/failure produce no audit events" (critical) | **Confirmed → high** | Real compliance gap and forensics blind spot, but it's a detection/visibility deficiency rather than a directly exploitable vuln, and brute-force is at least throttled by the login rate-limit. High is appropriate. |
| SOC | "User create/delete/password change not audited" (critical) | **Confirmed → high** | Real gap, but no auth bypass or privilege escalation. Audit-trail completeness issue. High is appropriate. |
| SOC | "GDPR right-to-erasure" (high) | **Confirmed → medium** | Real architectural gap, but MobInspect is an internal/self-hosted staff security-scanning tool — acute Art.17 risk is bounded. Medium fits a self-hosted single-tenant tool. |
| SOC | "Audit log captures X-Forwarded-For without verification" (high) | **Confirmed → medium** | Real bug. Corrupts attribution but doesn't bypass authn/authz, doesn't affect django-ratelimit (which uses Django's default key). A forgeable attribution field on an authenticated admin app without a privilege-escalation path isn't a "high". |
| SOC | "No threat model document" (high) | **Confirmed → medium** | Real documentation gap but not an exploitable defect — there's no evidence underlying mitigations are missing, only that no document enumerates them. |
| NOC | "SQLite delete-mode deadlocks under multi-user load" (critical) | **Confirmed → high** | Real defect. Slightly overstated as "critical" for a single-host LAN tool with one gunicorn worker — degraded UX and intermittent ORMQ enqueue failures rather than data loss or compromise. High is more accurate. (Fix is still trivial and in C5.) |
| NOC | "Web service runs scans synchronously" (critical) | **Confirmed → high** | Real defect. Severity downgraded for a single-tenant LAN appliance, but the misconfiguration is documented in the unit's own comment and the fix is trivial — still acted on. (See C6.) |
| NOC | "Web service has been OOM-killed" (high) | **Confirmed → high** | Verified in the live journal. Real availability impact. |
| Android | "ANDROID_API_SUPPORTED=30 ceiling" (critical) | **Confirmed → high** | Real architectural constraint. Severity downgraded because for a security-analysis tool dynamic analysis on Android 11 is still a usable product surface — many customer apps still run there. The proper fix is large; the immediate fix (surface honest error in UI) is trivial. |
| Android | "system_check returns False silently" (high) | **Confirmed → medium** | Real UX bug — misleading "Cannot Connect" instead of "API > 30 not supported". Observability issue, not exploitable. |
| Android | "Frida server downloaded at scan time with no SHA256" (high) | **Confirmed → medium** | Real but bounded: binary lands in disposable analysis emulator (not the host), and HTTPS-to-GitHub-releases is the canonical install path. Supply-chain blast radius is bounded; offline/air-gapped usability gap and version-without-hash-pinning are still worth fixing. |
| Android | "TLS pinning bypass missing coverage" (high) | **Partial → medium** | Verified gap in the default auto-loaded script. Coverage/false-negative issue in a security analysis tool, not an exploitable vulnerability in MobInspect itself. |
| Android | "CA injection doesn't run update-ca-certificates / rebuild APEX" (high) | **Partial → low** | Most issues unreachable: `ANDROID_API_SUPPORTED=30` gate means APEX overlay and `/data/misc/keychain/cacerts-added` paths aren't current pain points. "update-ca-certificates" framing is wrong — that's a Debian helper, not an Android command. Real impact is largely future-work for the API ceiling lift. |
| Founder | "Highest-value pages still render legacy AdminLTE" (critical) | **Partial → high** | Two specific files (`android_binary_analysis.html`, `ios_binary_analysis.html`) actually extend `base/app.html`, but their content is full of AdminLTE classes, so the user-facing claim is verified. Product-judgment call; no security/functional defect. High fits a conventional severity scale. |
| Founder | "User creation only offers legacy groups" (high) | **Confirmed → medium** | UX/onboarding defect, not a security flaw. Default fallback is Viewer (least-privilege safe), no privilege escalation. |
| Founder | "pyproject.toml lists upstream MobSF as repository/Bug Tracker" (high) | **Confirmed → medium** | Real branding/metadata leak in build artifacts, but not a security vulnerability and invisible until package is built/published. |
| Founder | "No SARIF/JUnit export" (high) | **Confirmed → medium** | Real product gap. Medium rather than high because absence-of-feature is roadmap material, not a security defect. |
| Founder | "No OIDC, SAML is the only SSO" (high) | **Partial → medium** | Technical evidence accurate but Okta/Azure AD/Google Workspace all support SAML in enterprise tiers, so customers aren't technically blocked — only inconvenienced. Roadmap item, not release blocker. |
| Investor | "SQLite multi-worker scalability ceiling" (high) | **Confirmed → high** (no change) | Real ceiling; verified all factual claims. Properly aimed at a 50-user pilot scenario. |

The pattern: several teams overstated severity on issues that are real but bounded (e.g., \"the bug exists but compensating controls limit blast radius\"). Code Auditor and Founder also occasionally conflated cleanliness/branding issues with security. The adversarial pass corrected for this without dropping the underlying findings — every refuted/downgraded item still appears in the action plan if it's a real defect, just at honest severity.

---

## Recommendations by team

**Coder.** Highest leverage is closing the half-finished work: (1) fix the production MIDDLEWARE in one diff (drop MIDDLEWARE_CLASSES + dead SessionAuthenticationMiddleware, add SecurityMiddleware/Common/XFrame/Ratelimit, tighten ALLOWED_HOSTS, ~30 min); (2) write a minimal pytest suite for RBAC + Analytics (~10-15 tests, blocks the next bug class from shipping); (3) finish the MOBSF_* → MOBINSPECT_* env rebrand in a single pass through settings.py; (4) pick the new RBAC and write a deprecation timeline for the legacy `permission_required(Permissions.X)` decorators. Use the RBAC module's quality bar as the style template for cleanups elsewhere.

**DevOps.** TLS+nginx in front, backup unit+timer for `~/.MobInspect/`, `/healthz` endpoint, harden systemd units (`MemoryMax`, `ProtectSystem=strict`, `ReadWritePaths`), and resolve the docker-vs-systemd dual track (delete the docker tree or rewrite it to mirror systemd). The recent commit cadence (StaticAnalyzer migrations + AVD writable-system + drop-in) shows the right incident-driven discipline — formalize it: add a `## Postmortems` section to RUNBOOK.md with one bullet per resolved SEV.

**Founder.** Finish the rebrand on the value-pages (scan reports + dynamic analyzer + PDF wordmark) before any sales motion. Stand up a public marketing surface (mobins.appdirs.in landing + pricing + contact + hosted demo). Fix the brand-leakage that points researchers at upstream (SECURITY.md, SUPPORT.md, update-check URL, pyproject metadata). Ship SARIF+JUnit export and webhook notifications — the two integrations that turn MobInspect from "standalone scanner" into "enterprise DevSecOps tool". Decide GPL-3.0 commercial posture with outside counsel before any external pilot.

**Investor.** Commission the GPL-3.0 monetization legal memo; without it every commercial conversation stalls. Harden production for external exposure (TLS, default-creds removal, ALLOWED_HOSTS, basic /healthz + Sentry) in 5 days. Hire a second engineer to write the missing test suite — fixes bus-factor=1 and zero-coverage simultaneously. Produce a 5-page commercial deck (TAM evidence, 3 named competitors with differentiation, pricing model, named pilot pipeline, 18-month revenue model). Define and ship one non-copyable moat feature (curated mobile threat-intel feed, hosted dynamic-analysis fleet, or compliance-mapped scan profiles) — without one, the fork is reproducible in two weeks by any contractor.

**Code Auditor.** Wire `@require_permission` onto the actual scan/dynamic/finding views OR prune the unenforced codenames — fix the catalog theatre. Add the missing baseline tests for RBAC. Fix the deploy landmines (README AVD specs, `scripts/clean.sh` deleting tracked migrations, `lxml` as explicit dep, `ALLOWED_HOSTS='*'`). Delete dead Django settings and the unused imports flagged by pyflakes. Decide on Gitea CI or document its absence.

**Security.** Fix the API auth bypass (the single most important diff in the entire repo). Stand up TLS+nginx. Validate `cmd` input on `execute_adb` / `ssh_execute` / `ssh_execute_device` and bind to new dangerous permissions. Remove default-cred banner; bump password floor to 12 chars; add django-axes. Add rate limiting to `/api/v1/*` keyed on the API key header. Enforce `api.use` permission in `api_auth`.

**SOC.** Wire Django auth signals (login_ok/fail/logout + create_user/delete_user/password_change) into `audit.record` — one afternoon of work. Add a JSON-lines audit forwarder (Python logger handler → journald → remote rsyslog/Loki) plus an Export CSV/JSON button on `/rbac/audit/`. Add tamper-evidence (`prev_hash` field, SQLite DELETE/UPDATE trigger, hourly `.backup` to off-host). Install django-axes for lockout + spike alerting. Write the missing docs: IR runbook, threat model, privacy policy with `manage.py user_erase`.

**NOC.** Enable SQLite WAL + busy_timeout (one settings change). Set `MOBSF_ASYNC_ANALYSIS=1` on the web unit drop-in. Add `/healthz` + external uptime probe. Fix systemd shutdown story (raise TimeoutStopSec, MemoryMax+swap, Restart=always with StartLimitBurst). Put nginx in front with TLS; bind gunicorn to 127.0.0.1. Logrotate `debug.log`; pin journald retention.

**Android Team.** Lock down `execute_adb` and add allowlists to every adb-shell endpoint. Bundle frida-server binaries with SHA256 verification; eliminate scan-time GitHub dependency; bound `spawn()` recursion. Automate AVD bootstrap (root + disable-verity + remount + readiness probe) as a systemd `ExecStartPre` so fresh deploys don't need a 5-step manual ritual. Either raise the API ceiling (with proper APEX/cacerts handling) or formally position the platform as "Android 11 / API 30 only". Extend TLS pinning bypass coverage (BoringSSL, Cronet, Flutter, RN) and report per-family bypass provenance.

---

## 30 / 60 / 90-day plan

### Days 0-30 (security and stability — must-fix before any external pilot)

| # | Item | Owner | Effort | Depends on |
|---|---|---|---|---|
| 1 | Remove `if api: return view(...)` in `permission_required`; apply `@require_permission` to /api/v1/* endpoints (C1) | Coder + Security | medium | — |
| 2 | Validate `cmd` in `execute_adb` / `ssh_execute` / `ssh_execute_device` with verb allowlist; gate behind new `dynamic.*.shell` dangerous permission (C2) | Android + Security | small | #1 |
| 3 | Stand up nginx + TLS (internal CA or LE) in front of gunicorn; rebind gunicorn to `127.0.0.1:8001`; ship systemd unit + config under `deploy/nginx/` (C3) | DevOps | small | — |
| 4 | Fix MIDDLEWARE: delete MIDDLEWARE_CLASSES, add SecurityMiddleware + Common + XFrame + Ratelimit; tighten ALLOWED_HOSTS via env var; set Secure cookies + HSTS + content-type-nosniff when DEBUG=False (C3, C4) | Coder | trivial | #3 |
| 5 | Enable SQLite WAL + busy_timeout in DATABASES['default']['OPTIONS'] (C5) | NOC | trivial | — |
| 6 | Add `Environment=MOBSF_ASYNC_ANALYSIS=1` to mobinspect.service.d/avd.conf (C6) | DevOps | trivial | #5 |
| 7 | Replace seeded `mobsf/mobsf` superuser with `manage.py bootstrap_admin` requiring `MOBINSPECT_ADMIN_PASSWORD`; remove "Default Credentials" banner; bump password min length to 12; refresh RUNBOOK (C7) | DevOps + Security | small | — |
| 8 | Raise `TimeoutStopSec` to 600s; add `MemoryMax=8G` + 4 GB swap; `Restart=always StartLimitBurst=5` on all three units (H1, H2, H6) | NOC | trivial | — |
| 9 | Add unauthenticated `/healthz` returning JSON `{db, queue, adb}`; wire into Dockerfile + systemd `ExecStartPost` + uptime monitor (H3) | DevOps + NOC | small | — |
| 10 | Fix `init.py:143` `create_roles` call (rename or update); add CI smoke test for `mobinspect db` (H23) | Coder | trivial | — |
| 11 | Fix `scripts/clean.sh` to not delete tracked migrations; invert `.gitignore *_migrations/_*` rule (H24) | Coder | trivial | — |
| 12 | Wire Django auth signals (login_ok/fail/logout) + audit.record on create_user/delete_user/password_change (H7) | SOC + Coder | small | — |
| 13 | Add rate limiting to /api/v1/* keyed on X-Mobsf-Api-Key; enforce `api.use` permission in api_auth; audit api.auth.fail (H8) | Security | small | #1 |

### Days 31-60 (quality, observability, brand)

| # | Item | Owner | Effort | Depends on |
|---|---|---|---|---|
| 14 | Write RBAC test suite: permissions, ApiKey lookup/expiry, signal mirror, escalation guard, decorator (anonymous/auth/api/dev-bypass), audit on denial (H17) | Coder | medium | — |
| 15 | Wire Gitea Actions CI: lint (flake8), test (pytest), migration check on every push to mobinspect (H30) | DevOps | small | #14 |
| 16 | Ship `mobinspect-backup.service` + `.timer` for hourly `sqlite3 .backup` + restic-to-off-host of `~/.MobInspect/{db.sqlite3, secret, uploads}`. Document restore in RUNBOOK with RPO/RTO (H4) | DevOps | small | — |
| 17 | Log rotation + journald retention drop-in (H5) | DevOps | trivial | — |
| 18 | Commission MobInspect wordmark; swap `mobsf_logo.png` / `mobsf_icon.png` + "MobSF" literal in `base_layout.html` (H18) | Founder + designer | small | — |
| 19 | Rewrite SECURITY.md / SUPPORT.md with security@appdirs.in + Gitea PR URL; repoint `GITHUB_URL` to Appdirs releases; update pyproject `repository` / `documentation` / `Bug Tracker`; accept both X-MobInspect-Api-Key and legacy header (H20) | Founder + Coder | small | — |
| 20 | Bundle frida-server binaries per arch into `deploy/binaries/`; pin SHA256; fail loud on mismatch; remove scan-time GitHub dependency; bound Frida.spawn() recursion (H12, H13) | Android | medium | — |
| 21 | Ship idempotent `deploy/scripts/avd-bootstrap.sh` (root + disable-verity + remount + boot_completed readiness); wire as `ExecStartPre=` on mobinspect-avd.service (H14) | Android + DevOps | small | — |
| 22 | Trusted-proxy / IP-source policy in `mobsf/RBAC/audit.py` (H16) | SOC | trivial | #3 |
| 23 | Audit-log JSON-lines forwarder via Python logger handler → journald → ForwardToSyslog; add Export CSV/JSONL button on `/rbac/audit/` (H10) | SOC | medium | — |
| 24 | django-axes (or equivalent) with username+IP lockout, exponential backoff, `account.locked` audit event; periodic django-q job for denial-spike → webhook (H11) | Security + SOC | medium | — |
| 25 | Audit scan upload/delete/rescan/PDF-export and Frida script upload/run (H7 extension) | SOC | small | #12 |
| 26 | Harden mobinspect-avd.service (NoNewPrivileges, PrivateTmp, ProtectSystem=strict, ReadWritePaths, ProtectKernelTunables) (H6) | DevOps | small | #21 |
| 27 | Resolve Docker-vs-systemd dual track (delete or rewrite to mirror systemd); gate upstream-targeted CI workflows on repo check (H29) | DevOps | medium | — |

### Days 61-90 (commercial readiness, finishing the rebrand)

| # | Item | Owner | Effort | Depends on |
|---|---|---|---|---|
| 28 | Migrate the ~16 legacy-AdminLTE templates to Tailwind/`base/app.html`: static binary/source analysis pages, dynamic-analyzer suite, apidocs (H19) | Founder + Coder | large | #18 |
| 29 | Replace User-create form with full Role dropdown; create `RoleAssignment` in `create_user` view (Founder broken-flow #10) | Founder + Coder | small | #14 |
| 30 | Finish MOBSF_* → MOBINSPECT_* env rebrand: route every `os.getenv` in settings.py through the env() shim; add CI test that both forms resolve identically (H31) | Coder | medium | — |
| 31 | Choose authorization system and execute deprecation: migrate every `permission_required(Permissions.X)` to `@require_permission`; delete `Permissions` enum + signals mirror + `can_scan/can_suppress/can_delete` (H25, H26) | Coder | large | #14 |
| 32 | Add SARIF + JUnit export to `/api/v1/scorecard` and `/api/v1/report_json` (H32) | Coder | medium | — |
| 33 | Add OIDC SSO via `mozilla-django-oidc` mirroring the SAML group→role map (H32) | Coder | medium | — |
| 34 | Webhook model + django-q hook for `scan.completed` / `finding.critical_added` JSON POSTs (H32) | Coder | medium | #16 |
| 35 | Tamper-evidence on AuditEvent: `prev_hash` field + SQLite trigger refusing UPDATE/DELETE (H9) | SOC + Coder | medium | #14 |
| 36 | DR runbook + first restore drill (H4 follow-up) | DevOps + Founder | small | #16 |
| 37 | Commercial: stand up `mobins.appdirs.in` landing + pricing + contact + hosted demo. Commission GPL-3.0 monetization legal memo. Write 5-page commercial deck. (H32, H33) | Founder | large | — |
| 38 | `manage.py user_erase` (anonymize AuditEvent.actor instead of NULL; redact ip_address tail octets; revoke ApiKeys; remove uploads/) + docs/privacy.md (SOC) | SOC + Coder | medium | #16 |
| 39 | API ceiling: investigate Magisk-on-AVD / Corellium for newer APIs, OR ship "Android 11 / API 30 only" as documented constraint with honest UI error (H21) | Android | large | — |

---

## Appendix: methodology

This report was produced via a three-phase multi-team adversarial pattern:

**Phase 1 — Inventory.** A scanner walked the repository (`/home/ubuntu/Desktop/Mobile-Security-Framework-MobSF`) and produced a structured fact-pack: LOC counts, app inventory with key files, deployment unit list, recent commit history, and key observations. This grounded all later analysis in the same shared facts.

**Phase 2 — Nine independent team audits.** Nine specialist personas — Coder, DevOps, Founder, Investor, Code Auditor, Security Team, SOC, NOC, Android Team — each independently audited the codebase from their perspective. Each produced a structured report with `findings` (severity, area, evidence, recommendation, effort), `gaps` (what's missing), `broken_flows` (end-to-end failures with symptom + fix), and `top_priorities`. Teams did not see each other's outputs during their pass, so convergence on issues across multiple teams is a high-confidence signal (e.g., the plaintext-HTTP and API-auth-bypass findings were independently raised by 5+ teams and 4 teams respectively).

**Phase 3 — Adversarial verification.** Every critical and high finding from Phase 2 was independently re-verified against the live codebase and (where possible) against the production host at 192.168.2.118. The verifier checked: does the cited file:line match the claim? Is the inferred impact accurate? Are there compensating controls the team missed? Is the recommended fix correct? Verdicts were `confirmed`, `partial`, or `refuted`, with adjusted severity where appropriate. Of ~75 critical/high findings reviewed, ~60 were confirmed at-or-near-claimed severity, ~12 were confirmed but downgraded (typically because compensating controls limit blast radius, or because severity inflation conflated cleanliness with security), and 1 was refuted outright (`timezone.timedelta does not exist` — Django actually does re-export it).

**Phase 4 (this document) — Synthesis.** Only confirmed findings made the action plan; refuted findings appear in the "What was refuted" section for calibration. Where multiple teams flagged the same issue, the strongest evidence and recommendation were merged. Severity was set by the adversarial verdict, not by the originating team's optimism or pessimism. Priorities (P0/P1/P2/P3) were assigned based on (a) reachability of the failure mode in the deployed configuration, (b) blast radius, and (c) effort relative to risk-reduction.

The pattern's strength is that it catches both the misses of any single perspective (a Security team might miss documentation gaps a Founder catches; an Investor might miss memory-cgroup issues an NOC catches) and the systematic overstatement that any single perspective tends toward when looking for things to flag. Its limitation is that it depends on the verifier being skeptical-but-fair; refuted findings should be re-checked any time the verifier's reasoning looks thin.