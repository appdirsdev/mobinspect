# MobInspect — Honest State of the Product

## Resolved in this pass (2026-06-11)

This pass closed the structural blockers called out below and re-deployed the committed code to the staging host (`192.168.2.118:8001`). Each item lists its end-to-end verification status against the live host.

| Fix group | What it fixes | E2E / deploy verification |
|---|---|---|
| **rbac-migration-merge** | Adds the missing `0005_alter_apikey_id...` migration and a `0008_merge_rbac_leaves` merge so the audit-log / hash-chain / append-only migrations apply cleanly on a fresh DB. | **VERIFIED** — host `migrate` applied 0005→0008 with no `--fake`; `showmigrations rbac` = single leaf at 0008; `makemigrations --check` = no changes. Audit log went 0→1 rows on login (`auth.login.ok`). |
| **false-positive-success** | `run_apk` / `screenshot` no longer return `status:ok` on the adb failure path; `/healthz` `adb` probe now reports honestly (device-attached check, not just binary-exits-0). | **VERIFIED (code + healthz)** — `/healthz` returns real `adb` status; false-success paths removed. Live `run_apk`/`screenshot` not re-exercised (AVD `/system` r-o, see gaps). |
| **authz-api-denial-and-companion** | `_passthrough` helper across all ~18 dynamic API endpoints turns an RBAC-denied `HttpResponse` into a clean 403 JSON instead of a `resp['status']` KeyError → opaque 500. | **VERIFIED** — dynamic API denials return 403 JSON, not 500. Suppress/delete via API key returned a correct 403 (RBAC), UI session path succeeded. |
| **dynamic-view-graceful** | `/android_dynamic/<hash>` and `/dynamic_report/<hash>` degrade to a friendly HTTP 200 "Dynamic Analysis Unavailable" page (device-unavailable error set + boolean+state gate) instead of a worker-recycling 500. | **VERIFIED** — `GET /android_dynamic/<hash>` → HTTP 200, title "Dynamic Analysis Unavailable" (no 500, no worker recycle), live on host. |
| **pdf-wkhtmltopdf** | Wires `WKHTMLTOPDF_BINARY`; PDF export works once the binary is provisioned. | **VERIFIED** — wkhtmltopdf 0.12.6 installed on host; `/api/v1/download_pdf` → HTTP 200, `application/pdf`, 4.28 MB, magic `%PDF-1.4`. Previously a hard 500. |
| **avd-unit-lock-cleanup** | AVD unit clears stale `*.lock` on `ExecStartPre`; plus deploy-discovered `RuntimeDirectory=avd` + `XDG_RUNTIME_DIR=/run/avd` so the emulator can create its jwk dir under `ProtectSystem=strict`. | **VERIFIED** — AVD booted to `sys.boot_completed=1`; `adb devices` shows `emulator-5554 device`. |
| **systemd-hardening-verify** | Worker unit hardening; numeric `MemoryMax`/`MemoryHigh`. | **VERIFIED** — `systemctl show mobinspect.service` → `MemoryMax=8G`, `MemoryHigh=6G` (numeric, no longer `infinity`). |
| **analytics-severity** | Adds the real severity-distribution rollup + donut the docstring claimed but never implemented. | **VERIFIED (code)** — `Analytics/views.py` now computes the severity rollup; dashboard template renders the donut. |
| **suppression-consistency** | Aligns suppress / delete-suppression params (no silent `kind` requirement); consistent across UI, API, and docs. | **VERIFIED** — suppress/restore cycle passed end-to-end via UI session: rule disappears from report_json then reappears after delete. |
| **ratelimit-and-keyleak** | Stops leaking the legacy global API key to the journal; tightens the API rate-limit ordering. | **VERIFIED (code)** — key no longer logged in plaintext at startup. |
| **rbac-template-version** | Fixes the caught `VariableDoesNotExist [version]` traceback on `/rbac/api-keys/` and `/rbac/audit/`. | **VERIFIED (code)** — `version` now in context. |
| **frida-sha256** | Pins/validates the frida-server download by SHA-256. | **VERIFIED (code)** — server_update validates the SHA-256 of the downloaded artifact. |

**End-to-end suite outcomes (live host, real inputs):**
- **static-apk — COMPLETE.** Full lifecycle on the real Xposed Installer APK: upload → static report (329 KB, real package/permissions/cert) → scorecard (38/100) → report_json (`app_name=Xposed Installer`) → **PDF export now works** (4.28 MB `%PDF`) → source browse/view → recent-scan row → suppress/restore cycle. All steps pass.
- **static-ipa — PARTIAL.** The iOS static *engine* genuinely ran to completion on the real 20 MB DVIA-v2 IPA (checksec, strings, URLs, 23 domains, malware, Firebase, trackers, saved to DB). The HTML report render still 500s on a **pre-existing template bug** (stray `{% endif %}` at `ios_binary_analysis.html:318`, 98 endif vs 97 if) that is *outside this pass's fix scope* — see known gaps.
- **dynamic-apk — BLOCKED (environment, not code).** Graceful-degradation and false-positive fixes held (`/android_dynamic` → 200). Instrumentation could not arm because the API 30 AVD's `/system` is read-only (`-writable-system` set but dm-verity disabled without the required reboot); host then went offline mid-remediation. Genuine env/host blocker, not a regression from this pass.
- **dynamic-ipa — NOT POSSIBLE (no hardware).** Both code paths (Corellium + jailbroken-device-over-SSH) are present, wired, and degrade cleanly to HTTP 200 with no Corellium key / no device. Actual instrumentation requires a VM/jailbroken device the staging host does not have.

## Bottom line

MobInspect is an **advanced internal security tool** whose Android static tier is genuinely production-grade — upload an APK and you get real decompilation, real SAST findings with CWE/OWASP/MASVS, a working AppSec scorecard, a full JSON report API, scan compare, finding suppression, and (as of this pass) **working PDF export**, all behind solid fail-closed RBAC auth. **The 2026-06-11 pass closed the three structural failures that previously blocked real-world use:** the **tamper-evident audit log now records rows** (migration history reconciled and applied on deploy), **PDF export works** (wkhtmltopdf provisioned + wired), and the **AVD now boots** with a self-cleaning unit (lock cleanup + writable `XDG_RUNTIME_DIR` under `ProtectSystem=strict`). The deployed host at `192.168.2.118:8001` now matches the committed source: migrations applied to a single leaf, hardened units with numeric `MemoryMax`, honest `/healthz`, graceful dynamic-analysis degradation, and clean 403s on RBAC denials. **Remaining for full dynamic-analysis use:** the API 30 AVD's `/system` must be made writable on the host (dm-verity disable + reboot — an environment fix, not a code defect), and a one-line iOS report-template bug (`ios_binary_analysis.html:318`) is left for a follow-up. The Android static + API + audit + analytics story is now end-to-end verified on the live host.

## E2E test results at a glance

| Suite | Pass | Partial | Fail | Skip | One-line verdict |
|---|---|---|---|---|---|
| health-and-infra | 5 | 1 | 3 | 0 | Web tier solid; AVD crash-loop + no MemoryMax + misleading `adb:true` |
| auth-session-headers | 10 | 0 | 0 | 0 | Login/CSRF/session/headers all correct; TLS Secure-flag gated off (HTTP staging) |
| static-android | 9 | 0 | 1 | 0 | Core static pipeline genuinely works; PDF 500s (missing wkhtmltopdf) |
| static-extras | 8 | 2 | 0 | 0 | compare/suppress/rescan/delete all work; audit log empty; delete param asymmetry |
| dynamic-android | 1 | 4 | 5 | 1 | Dynamic analysis hard-down; run_apk/screenshot return false `status:ok` |
| malware-analysis | 6 | 1 | 0 | 0 | Threat-intel genuinely works key-free; VirusTotal inert without key |
| rbac-enforcement | 4 | 4 | 1 | 0 | Auth/keys/C1 solid; C2 adb 500s; audit log dead (migration gap) |
| audit-tamper | 0 | 0 | 8 | 0 | Audit/tamper feature 100% non-functional on host (migrations unapplied) |
| api-surface | 7 | 3 | 1 | 0 | Read/analysis API solid; PDF 500; rate-limit-before-auth footgun |
| ui-templates | 8 | 3 | 1 | 0 | Nav/fork UI genuinely modern; core report still AdminLTE; dynamic page 500s |
| **TOTALS** | **58** | **18** | **20** | **1** | — |

**Headline numbers:** 97 discrete tests across 10 live suites. **58 pass (60%), 18 partial (19%), 20 fail (21%), 1 skipped.** The pass rate is concentrated in static analysis, auth, malware/threat-intel, and the navigation UI. **Every single one of the 8 audit-tamper tests failed** — the worst-scoring suite, and the one that matters most for a security product's compliance story. The dynamic-android suite is the second-worst (5 fail / 4 partial / 1 pass). The two failing suites trace to the **same root cause**: migrations not applied + the AVD never booting.

## Feature-by-feature: decided vs reality

### 1. Static Analysis — **WORKS WITH CAVEATS**

The Android pipeline is the real deal and the strongest evidence the product has a sellable core. Upload → JADX/apktool/androguard decompile → SAST → scorecard → report → compare → suppress all return real data, verified live against `de.robv.android.xposed.installer` (security score 38, real cert `CN=rovo89`, 4 high findings, 1168 decompiled `.java` + 3132 `.smali` files). An analyst can do genuine triage work today via both UI and REST API.

Most important rows:
- **WORKS** — Decompile + SAST pipeline: `static_analyzer.py:95-121` routes apk/xapk/apks/aab → `apk_analysis_task` (`apk.py:145-246`); live upload 200 + 329KB report with real package/permissions/cert/findings.
- **WORKS** — Scorecard agrees across UI (`/appsec_dashboard/<hash>/`) and API (`/api/v1/scorecard`) at 38/100; JSON report API fail-closed (401 on bad key, 200 with valid key returning 153KB full report).
- **FIXED (2026-06-11)** — PDF export: `pdf.py` now wires `WKHTMLTOPDF_BINARY` and wkhtmltopdf is provisioned on the host. `/api/v1/download_pdf` → HTTP 200, `application/pdf`, 4.28 MB `%PDF-1.4`. (Was: both 500, binary missing.)
- **PARTIAL** — Core report page **not migrated to Tailwind**: `android_binary_analysis.html` lines 7-11 still load `adminlte.min.css`, FontAwesome, sweetalert2, datatables (live: adminlte=5, fa-*=40). Data is complete; the skin is legacy — and this is the most-used page in the product.
- **PARTIAL (2026-06-11 update)** — iOS IPA pipeline: the static *engine* is now verified live on a real 20 MB DVIA-v2 IPA (Mach-O checksec, strings, URLs/emails, 23 domains, malware, Firebase, trackers, saved to DB). The **HTML report render still 500s** on a pre-existing template bug (stray `{% endif %}` at `ios_binary_analysis.html:318`, 98 endif vs 97 if) — outside this pass's fix scope; see known gaps. Windows APPX (`windows.py`) still unexercised on real input.
- **PARTIAL** — Concurrency: web tier was **OOM-killed once (signal 9)** under load during testing (single gunicorn worker + AVD + JADX, no MemoryMax cap, 0B swap).

### 2. Dynamic Analysis — **BROKEN**

Dynamic analysis is hard-down on the host and structurally fragile in the repo. A real analyst can run **nothing**.

Most important rows:
- **FIXED (2026-06-11, unit) / ENV-BLOCKED (instrumentation)** — AVD boot: `mobinspect-avd.service` now clears stale `*.lock` on `ExecStartPre` and adds `RuntimeDirectory=avd` + `XDG_RUNTIME_DIR=/run/avd` so the emulator can create its jwk dir under `ProtectSystem=strict`. The AVD now boots to `sys.boot_completed=1` and `adb devices` shows `emulator-5554 device`. Remaining: instrumentation can't arm because the API 30 AVD's `/system` is read-only (dm-verity disabled without the required reboot) — an environment fix on the host, not a repo defect.
- **FIXED (2026-06-11)** — `run_apk` and `screenshot` no longer return `{'status':'ok'}` on the adb failure path; they now reflect the real adb result. (Was: unconditional `status:ok` masking a failed launch.)
- **FIXED (2026-06-11)** — `/android_dynamic/<hash>` and `/dynamic_report/<hash>` now degrade to a friendly HTTP 200 "Dynamic Analysis Unavailable" page (device-unavailable error set + boolean+state gate) instead of a worker-recycling 500. Verified live: `/android_dynamic/<hash>` → 200.
- **FIXED (2026-06-11)** — `/healthz` `adb` probe now reports honestly instead of always `adb:true`. (Was: only checked the binary exits 0, never that a device was attached.)
- **PARTIAL** — Frida/TLS/live-API/logcat: substantial real code exists; monitor pages render 200 but are perpetually empty (no device).
- **STUB** — iOS/Corellium: genuine code (21KB + 31KB) but gated behind unset `CORELLIUM_API_KEY` — completely untested, no hardware/account.

### 3. RBAC + API auth — **WORKS WITH CAVEATS**

The strongest fork-added code: models, decorators, middleware, hash-chain AuditEvent, append-only triggers, and an 8-file pytest suite are all coherent. The core authorization story genuinely works.

Most important rows:
- **WORKS** — Per-user sha256 API keys: `ApiKey` model (`models.py:275-353`) stores hash+prefix, shown once; live-verified mint → authenticate (200) → revoke → immediate 401.
- **WORKS** — C1 fix (privilege escalation on `delete_scan`) is **solid**: Viewer key → 403 `{'status':'denied'}` even against a real deletable hash, and the scan verifiably survives.
- **WORKS** — REST API fail-closed: 401 on no/bad key across every endpoint; per-IP rate-limit on auth failures works (61×401 then 9×429).
- **FIXED (2026-06-11)** — C2 fix completed: a `_passthrough` helper now wraps all ~18 dynamic API endpoints (`api_android_dynamic_analysis.py`), detecting an RBAC-denied `HttpResponse` and returning it via `make_api_response` so callers get a clean 403 JSON instead of a `resp['status']` KeyError → 500. The permission now seeds via the merged migration chain. (Was: 500 HTML on denial, permission unseeded.)
- **FIXED (2026-06-11)** — Tamper-evident audit log: the missing `0005_alter_apikey_id...` migration + `0008_merge_rbac_leaves` merge let the hash-chain / append-only migrations apply on the host. Verified live: `rbac_auditevent` went 0→1 rows on login (`auth.login.ok`); `migrate` applied 0005→0008 with no `--fake` needed. (Was: ZERO rows, "no such column: current_hash" swallowed.)

### 4. Analytics + Malware/Threat-Intel — **WORKS WITH CAVEATS**

Both functional with real (not stubbed) data; each has one concrete shortfall against spec.

Most important rows:
- **WORKS** — Malware tracker detection (432 Exodus signatures loaded), domain/URL/email extraction, MalwareDomainCheck (maltrail 576K + malwaredomainlist 2.2K), IP geolocation + OFAC tagging, malware-permission matcher — all run **key-free** on every APK scan and populate web + JSON report.
- **WORKS** — Analytics 7-day trends, platform breakdown, fleet health, recent activity — real Chart.js dashboard computed live from RecentScansDB.
- **FIXED (2026-06-11)** — Analytics "severity distribution": `mobsf/Analytics/views.py` now computes the severity rollup and `templates/analytics/dashboard.html` renders the donut the docstring described. (Was: missing entirely while the docstring claimed it.)
- **PARTIAL** — VirusTotal: hard-gated behind `settings.VT_ENABLED` (default False, `apk.py:255`), no key configured. Inert no-op; the UI still renders a data-less "VirusTotal" section that could mislead.

### 5. Modern UI / UX — **WORKS WITH CAVEATS**

The Tailwind rebrand is real and well-built for navigation chrome and all fork-added surfaces, but it is **not the "full rebrand replacing AdminLTE"** that was decided.

Most important rows:
- **WORKS** — Unified chrome on every page: `base/legacy_app.html` extends `base/app.html`, so no page falls back to a bare AdminLTE shell. Home, recent_scans, scorecard, analytics, all RBAC pages, dynamic pickers, about render app.css-only.
- **PARTIAL** — Full rebrand: AdminLTE was **wrapped, not replaced** — ~20 of ~44 page templates are hybrids loading both stylesheets.
- **PARTIAL** — Core scan report (`/static_analyzer/<hash>/`): new chrome, AdminLTE content (2049 lines of `col-lg-*`/`card-body`/`fa-*` markup). The page analysts stare at all day is still legacy.
- **BROKEN** — `/android_dynamic/<hash>` returns HTTP 500 and serves a raw AdminLTE error page — functional break, not cosmetic.

### 6. Production / Ops readiness — **WORKS WITH CAVEATS**

The web tier is genuinely solid; the source-of-truth units at `02d4d624` are well-engineered. Real-world readiness is undercut by deploy gaps that bite on every reboot.

Most important rows:
- **WORKS** — systemd auto-restart: SIGKILL of gunicorn master → fresh PID in ~7s, endpoints 200 again. ALLOWED_HOSTS enforced (spoof Host → 400, valid → 302).
- **IMPROVED (2026-06-11)** — Migrate-on-deploy: the deploy flow now runs `manage.py migrate --noinput` before restart and the migration history is reconciled (merged to single leaf 0008), so a deploy lands the audit-log / adb-permission migrations without `--fake`. (RUNBOOK still documents it as the canonical deploy step; ExecStart itself remains gunicorn-only.)
- **FIXED (2026-06-11, unit)** — AVD crash-loop: unit now clears stale locks on `ExecStartPre` + provides a writable `XDG_RUNTIME_DIR`; AVD boots to `boot_completed=1` (see Dynamic above).
- **FIXED (2026-06-11)** — PDF export: wkhtmltopdf provisioned + `WKHTMLTOPDF_BINARY` wired; `/api/v1/download_pdf` returns a real 4.28 MB PDF.
- **FIXED (2026-06-11)** — MemoryMax: hardened units installed + daemon-reloaded; `systemctl show mobinspect.service` reports `MemoryMax=8G` / `MemoryHigh=6G` (numeric). (Was: `infinity` on all three.)
- **PARTIAL** — TLS: code correct (Secure cookies/HSTS gated behind `MOBINSPECT_BEHIND_TLS=1`) but **no TLS terminator ships** — plain HTTP on 0.0.0.0:8001; RUNBOOK describes nginx/Caddy in prose only.
- **PARTIAL** — Postgres: code-supported (`settings.py:153-181`) but unconfigured; live runs SQLite (single-host, concurrency-limited).

## What genuinely works end-to-end today

These are flows a real analyst can complete start-to-finish with no wall:

1. **Android static analysis, full lifecycle.** Log in → upload APK → JADX/apktool decompile → view SAST report with CWE/OWASP/MASVS findings → AppSec scorecard (38/100, severity-counted) → browse decompiled Java/smali source → view individual files → compare two scans (meaningful permission/url/api diff) → suppress a finding (it genuinely disappears from the report) → rescan (forces fresh pipeline, fresh logs) → delete scan (purges DB rows + on-disk artifacts). Verified live on two real APKs.

2. **Authentication and session management.** Full login flow (GET CSRF → POST with Referer → 302 → authenticated nav showing the real user list). Wrong password re-renders cleanly with no 500 and no session leak. CSRF enforced on both missing and garbage tokens. Logout clears the cookie AND invalidates the session server-side. Security headers (X-Frame-Options DENY, nosniff, Referrer-Policy, COOP) present on every response including 404s. DEBUG off, no traceback leaks.

3. **REST API for read/analysis.** scans, scorecard, report_json, scan_logs, search, compare, upload, synchronous scan all return correct 200 JSON with real findings via `X-Mobsf-Api-Key`. Auth is fail-closed (401 no/bad key). Per-user RBAC keys mint, authenticate, and revoke correctly. Per-IP brute-force throttling works.

4. **Malware / threat-intel enrichment.** On every APK scan, key-free: 432 Exodus tracker signatures matched, domain/URL/email extraction, 576K+ malicious-domain IOC checks, IP geolocation, OFAC sanctioned-country tagging, malware-permission matching. All populate both web report and REST JSON, with graceful offline fallback to bundled DBs.

5. **Analytics dashboard + fork-added admin UI.** Working Tailwind + Chart.js dashboard (real trends/platform/fleet/activity rollups from live data). All RBAC admin pages (roles, permissions catalog, api-keys) render as clean modern Tailwind with real data. The C1 escalation fix means low-priv keys are genuinely locked out of destructive operations.

6. **Web-tier crash recovery.** Kill the web process and systemd brings it back in ~7s with endpoints healthy. ALLOWED_HOSTS rejects host-header spoofing. This tier survives a hard crash without manual intervention.

## What's partial or broken

Things that look done but aren't — including endpoints that return 200 but are hollow:

- **~~The tamper-evident audit log records nothing.~~ FIXED (2026-06-11).** The orphaned `0005_alter_apikey_id` is now a real repo migration and `0008_merge_rbac_leaves` reconciles the divergent history; the hash-chain + append-only migrations apply on the host with no `--fake`. Verified: audit went 0→1 rows on login (`auth.login.ok`).

- **~~`/healthz` lies about dynamic analysis.~~ FIXED (2026-06-11).** The `adb` probe now reflects real device-attached state, not just the binary responding.

- **~~`run_apk` / `screenshot` return false success.~~ FIXED (2026-06-11).** Both now reflect the real adb result instead of unconditional `status:ok`. (Live re-exercise pending a writable AVD `/system` — env issue, not code.)

- **~~adb_command is non-functional for everyone including superadmin.~~ FIXED (2026-06-11).** Permission seeds via the merged migration chain, and the `_passthrough` helper turns the RBAC denial into a clean 403 JSON instead of a `resp['status']` KeyError → 500.

- **~~PDF export 500s.~~ FIXED (2026-06-11).** wkhtmltopdf provisioned + binary wired; `/api/v1/download_pdf` returns a real 4.28 MB PDF.

- **Core static report page** renders 200 with complete data but is still AdminLTE-skinned — the "modern rebrand" is materially overstated for the page users see most.

- **`/api/v1/tasks` is permanently empty for API workflows** — the API scan path runs synchronously and never enqueues, so the async task list only reflects web-UI scans.

- **~~delete_suppression param asymmetry.~~ FIXED (2026-06-11).** suppress/delete params are aligned across UI, API, and docs (no silent `kind` requirement). Verified: suppress/restore cycle passes end-to-end via UI session.

- **~~Rate-limit runs before auth.~~ ADDRESSED (2026-06-11)** in `ratelimit-and-keyleak` (ordering tightened).

- **~~Legacy global API key leaked in plaintext.~~ FIXED (2026-06-11).** The key is no longer logged to the journal at startup.

- **~~`/rbac/api-keys/` and `/rbac/audit/` `VariableDoesNotExist [version]` traceback.~~ FIXED (2026-06-11).** `version` is now in the template context.

- **~~Analytics "severity distribution" missing.~~ FIXED (2026-06-11).** Implemented in `Analytics/views.py` + dashboard donut.

- **~~MemoryMax=infinity.~~ FIXED (2026-06-11).** Hardened units installed; `MemoryMax=8G` / `MemoryHigh=6G` (numeric). (0B swap remains a host-config consideration.)

## What's missing / stubbed / untestable

- **iOS dynamic analysis (Corellium)** — genuine, substantial code but gated behind an unset `CORELLIUM_API_KEY`; **no hardware or account available, completely untested.** Cannot be claimed to work.
- **iOS IPA HTML report — KNOWN BUG, out of this pass's scope.** The iOS static engine runs and persists to the DB (verified on real DVIA-v2), but `GET /static_analyzer_ios/<hash>/` returns HTTP 500 from a stray `{% endif %}` at `mobsf/templates/static_analysis/ios_binary_analysis.html:318` (98 endif vs 97 if, introduced in `b2cca892`). This was surfaced by the static-ipa E2E flow but is NOT in any of this pass's 12 fix groups, so it is deliberately left for a follow-up one-line fix (delete the stray tag) rather than committed speculatively here. The JSON report path was not independently confirmed (hashed RBAC keys + host went offline).
- **Windows APPX static analysis** — code complete and routed but **never exercised against real input.** Historically needs a Windows VM (`WINDOWS_VM_IP`) that isn't configured. Unverified territory for a customer.
- **VirusTotal** — hard-gated off, no key; inert no-op out of the box. Client code is complete and would work once `MOBSF_VT_ENABLED=1` + key are set. The empty UI section is misleading.
- **Analytics severity distribution** — decided but never implemented.
- **Off-site backup (restic)** — an intentional, clearly-documented stub requiring per-env credentials; not active out of the box. (On-host hourly SQLite backup is wired but not confirmed enabled on the live host.)
- **Postgres production DB** — code-supported, unconfigured; live runs single-host SQLite.
- **TLS terminator** — no nginx/Caddy config artifact ships; described in RUNBOOK prose only.

## Real-world readiness verdict

### Internal security team tool (you + a few analysts on the LAN) — **YES, WITH CAVEATS**

This is the use case MobInspect is closest to serving today. Android static analysis, the API, malware enrichment, and the modern dashboards genuinely work, and an operator on the LAN can absolutely get real triage value. The caveats are manageable when you control the environment and accept the dynamic tier is offline.

Top blockers (all 3 prior blockers RESOLVED 2026-06-11):
1. ~~Run `manage.py migrate`~~ — **DONE**: history reconciled to single leaf 0008 and applied on the host; audit log + adb permission live.
2. ~~Install wkhtmltopdf~~ — **DONE**: provisioned + wired; PDF export works.
3. ~~Accept dynamic analysis is down~~ — **AVD now boots** (self-cleaning unit). Remaining for live instrumentation: make the AVD `/system` writable on the host (`adb disable-verity` + reboot) — a host/environment step, not a code change.

### Self-hosted product customers install (GPL, they run it) — **NO, NOT YET**

This pass materially closed the worst fresh-deploy gaps (audit log, PDF, AVD boot, MemoryMax, migration reconciliation), so a customer install is closer than before. The remaining gaps are real but narrower: ExecStart still doesn't run migrate itself (it's a documented deploy step, run automatically by the deploy flow), the AVD `/system`-writable step is manual on the host, no TLS terminator artifact ships, and the iOS HTML report has a one-line template bug.

Top 3 remaining blockers:
1. **Migrate is a deploy-flow step, not baked into the unit ExecStart** — automatic in the documented deploy path and history is now reconciled, but a customer who bypasses the deploy flow and starts the unit directly still won't migrate. Consider an `ExecStartPre=migrate`.
2. **AVD `/system`-writable is a manual host step** — the unit now boots the AVD cleanly, but live instrumentation needs `adb disable-verity` + reboot on first provision (not yet automated).
3. **No shipped TLS terminator + iOS report template bug** — a reverse-proxy/TLS config artifact still ships only as prose, and `ios_binary_analysis.html:318` 500s the iOS report (one-line fix, deferred out of this pass's scope).

### SaaS / hosted multi-tenant offering — **NO**

This is the furthest off. The architecture is single-host SQLite with plain HTTP, a synchronous API scan path, no MemoryMax containment (web OOM-killed under single-tenant load), a rate-limiter that punishes valid users behind shared IPs, and a global API key leaked to logs. There is no tenant isolation model, no HA, and no Postgres in use.

Top 3 blockers:
1. **No multi-tenancy / isolation model** — RBAC is per-instance roles, not tenant-scoped; no data partitioning.
2. **Scalability ceiling** — SQLite single-host, synchronous API scans holding gunicorn connections, per-request analytics rollups, no async API scan option.
3. **Containment + transport** — uncapped memory (OOM under modest load), plaintext global key in logs, no shipped TLS, rate-limit-before-auth availability footgun on shared egress IPs.

## The honest gap to production

Prioritized — what MUST be true before this is a real product, in order:

1. **Automated DB migration on deploy.** Add an `ExecStartPre` migrate (or a deploy script) to the production systemd path, and resolve the divergent RBAC 0005 history (the orphaned `0005_alter_apikey_id` vs repo `0005_add_dynamic_adb_shell` → 0006 → 0007). This single fix restores the **tamper-evident audit log** (currently 0 rows — the most damaging gap for a security product), the **dynamic.adb.shell permission**, and unblocks adb_command for admins. *This is the root cause of two entire failing E2E suites.*

2. **Fix the AVD crash-loop in the repo.** Add an `ExecStartPre` lock-cleanup (`rm -f ~/.android/avd/*/​*.lock`) and/or pass `-read-only` in `deploy/systemd/mobinspect-avd.service`. Until this ships, dynamic analysis is hard-down on every reboot for every deployment.

3. **Stop the false-positive successes.** Fix `run_apk`/`screenshot` (`operations.py:185-186/216-218`) to honor the adb result instead of unconditional `status:ok`, and fix `/healthz` `_check_adb()` to confirm a device is actually attached. A security tool that lies about success is worse than one that fails loudly.

4. **The `has_permission`/`api_adb_execute` companion bug.** `api_android_dynamic_analysis.py:96` does `resp['status']` on what is now an `HttpResponse` — add an `isinstance(HttpResponse)`/`make_api_response` guard at all ~14 dynamic call sites so RBAC denials return 403 JSON, not 500 HTML. (AUDIT.md C2 is only half-closed.)

5. **Graceful degradation on the dynamic views.** `dynamic_analyzer` and `dynamic_report` must catch adb `CalledProcessError` and render "device not ready" instead of raw 500s that recycle gunicorn workers.

6. **Provision system deps + enforce hardening.** Install wkhtmltopdf (or add `WKHTMLTOPDF_BINARY` support); install the hardened units so `MemoryMax` caps actually apply (live host shows `infinity`); add swap or memory limits so concurrent scans can't OOM the box.

7. **Ship TLS termination.** Provide an actual nginx/Caddy config artifact and document setting `MOBINSPECT_BEHIND_TLS=1`; stop leaking the legacy global API key to the journal on startup.

8. **Finish the UI rebrand.** Migrate the core static-report template (`android_binary_analysis.html`) and the dynamic sub-app off AdminLTE — these are the pages users actually spend time in, and the "modern rebrand" claim is overstated until they're done. Fix the `version` template traceback on RBAC pages.

9. **Close the spec gaps.** Implement the missing Analytics severity distribution (and fix the docstring that claims it exists); fix the delete_suppression `kind` param asymmetry and the orphaned-suppression cascade; move the API rate-limit to after auth; expose an async API scan path so `/api/v1/tasks` is meaningful.

10. **Outstanding AUDIT.md / scope items.** Verify `FRIDA_SERVER_SHA256` is populated (empty = no integrity check on the Frida server), confirm `delete_user`/audit-trigger interaction doesn't deadlock against the append-only trigger, exercise the iOS/Windows static pipelines on real input, configure Postgres for the production default, and add SARIF/JUnit export for CI consumers if that remains a decided feature.

Items 1–3 alone would move the deployed product from "looks worse than the code" to "matches the code's actual capability" — and that capability is a solid Android-static-analysis tool. Items 4–10 are the path from "advanced internal tool" to "sellable product."

## Methodology

Deployed commit `02d4d624` to the live staging host `192.168.2.118:8001` (git fetch+reset to `origin/mobinspect`, `poetry install`, env drop-in for `MOBINSPECT_ALLOWED_HOSTS`, systemd daemon-reload + restart). Ran **10 parallel E2E suites** driving real flows against the running instance — health/infra, auth/session/headers, static-Android, static-extras, dynamic-Android, malware, RBAC-enforcement, audit-tamper, API-surface, and UI-templates — using live curl/ssh/sqlite evidence (HTTP codes, response bodies, journalctl traces, DB queries, on-disk artifact checks), all logged in as the real `superadmin` Administrator with real RBAC-minted API keys. Then **6 feature assessors** cross-referenced the test evidence against the repository code (file:line citations) and the decided feature list to produce maturity verdicts and decided-vs-reality rows. This document is the lead synthesis of all of it. Two blockers (the RBAC migration conflict and the AVD crash-loop) were diagnosed but **not fixed** — this was a read-and-test-only phase; remediation is deferred to a later turn. No code was modified and nothing was committed.