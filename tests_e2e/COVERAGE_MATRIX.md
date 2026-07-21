# tests_e2e coverage matrix

Traceability: every reachable page and `/api/v1/*` endpoint -> the spec
file(s) exercising it. "100%" here means 100% of the surface that can
actually execute in this environment — the same honest scoping
`.coveragerc` already uses for the backend unit suite (see "Excluded"
below), not 100% of literally every URL pattern in `urls.py`.

Status legend: ✅ covered · 🚧 in progress · ⬜ not yet started

## UI pages

| Route | Spec file | Status |
|---|---|---|
| `/login/`, `/logout` | `ui/specs/test_smoke.py` (positive login), `ui/specs/test_auth.py` — negative (wrong password/username, empty submit blocked client-side), positive+regression (logout clears session, revisiting `/` bounces back to `/login/`) | ✅ |
| `/` (dashboard) | `ui/specs/test_dashboard.py` | ✅ |
| `/recent_scans/` | `ui/specs/test_dashboard.py` | ✅ |
| `/static_analyzer/<md5>/` (Android report) | `ui/specs/test_report.py` | ✅ |
| `/ai_dashboard/<md5>/` | `ui/specs/test_report.py` (positive + watermark, real generated content), `ui/specs/test_ai_dashboard.py` (negative: no-AIEnrichment / nonexistent / malformed checksum -> graceful redirect, never 500) | ✅ |
| `/analytics/` | `ui/specs/test_analytics.py` (KPIs, canvases, legends, buckets, hover, top apps, recent activity, **+ underlying Chart.js JSON data blobs asserted non-zero, not just canvas layout**) | ✅ |
| `/rbac/roles/`, `/rbac/roles/<id>/`, `/rbac/roles/new/`, `/rbac/roles/<id>/delete/`, `/rbac/roles/<id>/assign/`, `/rbac/roles/<id>/unassign/<uid>/` | `ui/specs/test_rbac.py` (render-only), `ui/specs/test_rbac_users.py` (create/edit/delete, duplicate-name reject, delete-role-in-use cascade, assign/unassign, nonexistent-user 404) | ✅ |
| `/rbac/permissions/` | `ui/specs/test_rbac.py` | ✅ |
| `/rbac/api-keys/`, `/rbac/api-keys/new/`, `/rbac/api-keys/<id>/revoke/` | `ui/specs/test_rbac.py` (render-only), `ui/specs/test_rbac_users.py` (create + one-time plaintext reveal + revoke) | ✅ |
| `/rbac/audit/` | `ui/specs/test_rbac.py` (render/filter/pagination), `ui/specs/test_rbac_users.py` (real role.create/role.delete event round-trip) | ✅ |
| `/users/`, `/create_user/`, `/delete_user/` | `ui/specs/test_rbac.py` (render-only), `ui/specs/test_rbac_users.py` (create/delete CRUD, duplicate-username reject, delete cascades role assignments) | ✅ |
| `/rbac/integrations/adb/` (ADB + model cards) | `ui/specs/test_integrations.py` — positive (4 fixed cards, Save&Test persists/status), **negative (public/non-enclave host rejected by `_host_is_enclave`, malformed URL rejected, empty model name rejected, invalid ADB host:port rejected)**, **regression (Not configured / Connected / Failed pills are genuinely distinct render paths, verified via a real local fake-Ollama HTTP server + a real unreachable loopback port)** | ✅ |
| `/about`, `/api_docs` | `ui/specs/test_general_dynamic.py` | ✅ |
| `/help/`, `/tasks` | `ui/specs/test_general_pages.py` | ✅ |
| `/find/` | `ui/specs/test_general_pages.py` — negative, `xfail(strict=True)`: confirmed live app bug, `find.run()` (mobinspect/StaticAnalyzer/views/android/views/find.py:37,49,76) always returns a raw `dict` on every error branch instead of an `HttpResponse`/`JsonResponse` (`print_n_send_error_response(..., True)`), which Django's response-processing middleware can't handle -> 500 on every error path; this environment also has no on-disk `java_source` for any seeded fixture (JADX artifacts aren't retained post-scan here) so even a real-hash query can't reach a 200 either. See the spec's module docstring for full detail; remove the xfail once find.py is fixed. | 🚧 |
| `/search` | `ui/specs/test_general_pages.py` — positive (`?query=Diva` redirects to the real report), negative (no query / no match -> the app's standard branded error page, not a traceback; note this template renders with HTTP 500 by design app-wide via `print_n_send_error_response`, so the negative assertion is "no traceback / clean error card", not a specific status code) | ✅ |
| `/healthz/`, `/readyz/`, `/robots.txt` | `api/specs/test_health_and_misc.py` | ✅ |
| `/change_password/` | `ui/specs/test_auth.py` — positive (renders; real form submit changes the password for a throwaway ORM-provisioned user, verified via `check_password()`, never touches `admin`) | ✅ |
| `/compare/<h1>/<h2>/` | `ui/specs/test_general_pages.py` — positive (PRIMARY_HASH apk vs SECONDARY_HASH jar -- both have a `StaticAnalyzerAndroid` row, the only requirement `comparer.generic_compare` actually checks, confirmed live), negative (same hash, two well-formed-but-nonexistent hashes, malformed hash segment -> plain Django 404) | ✅ |
| Suppressions UI (report-page "Suppress" button -> `/suppress_by_rule/`, `/suppress_by_files/`, `/list_suppressions/`) | Covered at the API layer (`api/specs/test_suppressions.py`, real e2e_flow) — the UI *click* interaction on the report page's findings table itself has no dedicated Playwright spec yet. | 🚧 |
| Android/iOS dynamic-analysis landing pages | `ui/specs/test_general_dynamic.py` | ✅ (render-only, documented exclusion) |

## API v1 (non-hardware-dependent)

| Endpoint | Spec file | Status |
|---|---|---|
| `upload`, `scan` | `api/specs/test_upload_scan_flow.py` — e2e_flow (scratch upload -> scan -> poll report_json -> download_pdf -> delete_scan -> 404), negative (missing file field, invalid/nonexistent hash, missing hash), regression (duplicate-upload 409 envelope) | ✅ |
| `report_json` | `api/specs/test_scaffold_smoke.py` (smoke), `api/specs/test_report_json.py` — positive across all 11 `SCANNED` formats (Android/iOS/Windows shape differences asserted + jsonschema), negative (missing/malformed/nonexistent hash) | ✅ |
| `scorecard` | `api/specs/test_scorecard.py` — positive (apk + 6 other formats, jsonschema), negative (appx unsupported, missing/malformed/nonexistent hash) | ✅ |
| `download_pdf` | `api/specs/test_download_pdf.py` — positive (apk + jar/ios_src/appx, `%PDF` magic bytes), regression (no tamper-error false positive, pins commit 21666f3), negative (missing/malformed/nonexistent hash) | ✅ |
| `scans`, `search`, `compare` | `api/specs/test_scans_search_compare.py` — positive (scans list contains PRIMARY, search by name/hash, compare apk vs jar), negative (search no-match, compare Android-vs-iOS / same-hash / missing params) | ✅ |
| `list_suppressions`, `suppress_by_rule`, `delete_suppression` | `api/specs/test_suppressions.py` — e2e_flow (scratch scan: list empty -> suppress real manifest rule -> list shows it -> delete -> gone), negative (missing params, invalid type, malformed/nonexistent hash) | ✅ |
| `delete_scan` | `api/specs/test_scaffold_smoke.py` (RBAC-denial case), `api/specs/test_upload_scan_flow.py` (real delete as part of the e2e_flow), negative (missing/malformed/nonexistent hash) | ✅ |
| RBAC contract (401/403 matrix across all of the above) | `api/specs/test_scaffold_smoke.py` (pattern), `api/specs/test_rbac_api_contract.py` — full 3-layer matrix (middleware 401/403, RBAC-decorator 403, legacy-decorator 403) x (anon/Viewer/API User/Administrator) across `report_json`, `scorecard`, `compare`, `list_suppressions`, `download_pdf`, `scans`, `search`, `delete_scan`, `suppress_by_rule`, incl. a scratch-scan e2e_flow for the two legacy-guarded mutating endpoints | ✅ |

## Excluded (documented, same convention as `.coveragerc`)

- `api/v1/android/*`, `api/v1/frida/*` — needs a live Android device/emulator + Frida.
- `api/v1/ios/*`, Corellium endpoints — needs a live Corellium instance or jailbroken device.
- `api/v1/dynamic/*` (Android/iOS dynamic report) — needs a live device to have produced a dynamic scan.
- Windows PE analysis views — needs a Windows host.

## Backend Python coverage (`.coveragerc` scope)

See `.coveragerc` at the repo root for the omitted (hardware/vendor-locked)
modules. Verified via a FRESH (non-`--reuse-db`) full real-execution run —
see "reuse-db gotcha" note below before ever trusting a `--reuse-db` number:

```bash
set -a; . ./.env.postgres; set +a
export POSTGRES_DB=mi_verify MOBINSPECT_JADX_BINARY="$HOME/.MobInspect/tools/jadx/jadx-1.5.0/bin/jadx"
poetry run coverage run --parallel-mode -m pytest -q --continue-on-collection-errors \
  $(find mobinspect \( -name "test_cov_*.py" -o -name "test_integration.py" \) | grep -viE androguard4)
poetry run coverage combine && poetry run coverage report --show-missing
```

**Last verified total: 100.0%** (12337 stmts / 0 missing), 2380 tests passing,
0 failures — independently reproduced on TWO separate fresh runs (isolated
databases, ~10-12 min each) with byte-identical results, after a prior
in-session `--reuse-db` run had shown a corrupted, misleading 98.8%/148-missing
figure (see the "reuse-db gotcha" below — that number was an artifact, not a
real gap; no source or test code changed between the two figures).

**Scope honesty check:** this 100% is 100% of the `.coveragerc`-scoped
subset only — DynamicAnalyzer (~10k lines), Windows-only views/install
(~1.8k lines), and vendored androguard4 (~8.6k lines) are excluded from the
denominator for stated, verified reasons (need live hardware/OS or are
third-party code), totaling roughly **45% of the codebase's lines excluded**.
All 98 `# pragma: no cover` annotations elsewhere in the scoped code were
individually audited and carry specific, verifiable justifications (live
network calls, hardware-locked, Windows-only branches, or provably
unreachable code) — none were added to game this number.

**reuse-db gotcha:** `--reuse-db` against a test DB previously touched by a
`TransactionTestCase` that flushes RBAC seed data produces mass, UNRELATED
failures on the next run (cascading 403s etc.) — this looks like a
regression but isn't. Always use a FRESH db (drop `--reuse-db`) for any
authoritative full-suite coverage number; only use `--reuse-db` for quick
iteration on a single file you already know passes clean.
