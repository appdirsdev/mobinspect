# tests_e2e — MobInspect automation suite (UI + API)

Real-execution end-to-end automation against a **running** MobInspect
server: Playwright browser tests for the UI, and live HTTP calls (no Django
test client, no mocks) for the REST API. Deliberately **outside**
`pyproject.toml`'s `testpaths`, exactly like the `tests_ui/` suite this
replaces — the unit suite (`scripts/run-tests.sh`) never collects this, run
it explicitly.

## Folder structure

```
tests_e2e/
  conftest.py            shared config: base URL, admin creds/key (env-driven)
  fixtures/
    data.py               single source of truth for scanned-sample hashes
                           and test_files/ paths — every spec reads from here
  ui/                      Playwright browser suite
    conftest.py            admin_page / admin_context / storage_state fixtures
    pages/                 Page Object Model — one class per page/section
    specs/                 test_*.py, one file per feature area
  api/                     live-HTTP REST contract suite
    client.py              MobInspectApiClient — thin requests wrapper
    conftest.py            api_client / anon_api_client / viewer_api_client / ...
    schemas/               jsonschema definitions, one per response shape
    specs/                 test_*.py, one file per resource
```

## One-time setup

```bash
poetry install                     # pulls pytest-playwright, playwright, jsonschema, coverage
poetry run playwright install chromium
```

## Seeding test data

Every hash in `fixtures/data.py` is a REAL scan. Seed a fresh DB once by
scanning each fixture in `test_files/` (via the UI upload or
`api_client.upload_apk()` + `.scan()`), then update the hashes in
`fixtures/data.py` if the seeded MD5s differ from what's checked in (they
won't, unless a fixture file's bytes changed — MD5 is content-derived).

## Running

Start a real server first — MobInspect refuses Django's `runserver` outside
`MOBINSPECT_DEV=1` (see `manage.py`); use gunicorn like production does:

```bash
source .env.postgres
export MOBINSPECT_AI_ENABLED=1
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES   # macOS only — gunicorn+Cocoa fork crash
poetry run gunicorn -b 127.0.0.1:8000 mobinspect.MobInspect.wsgi:application --workers=1 --threads=4 --timeout=180 &
poetry run python manage.py qcluster &            # background worker, for async scans
```

Then, in another shell:

```bash
# whole suite (UI + API together)
poetry run pytest tests_e2e/ --browser chromium -q -o addopts=""

# UI only / API only
poetry run pytest tests_e2e/ui/ --browser chromium -q -o addopts=""
poetry run pytest tests_e2e/api/ -q -o addopts=""

# slice by test-type marker (see "Test taxonomy" below)
poetry run pytest tests_e2e/ -m "negative" -q -o addopts=""
poetry run pytest tests_e2e/ -m "regression and not preprod" -q -o addopts=""
```

Override target/creds via env: `MOBINSPECT_UI_BASE`, `MOBINSPECT_ADMIN_USERNAME`,
`MOBINSPECT_ADMIN_PASSWORD`, `MOBINSPECT_ADMIN_API_KEY` (skips auto-provisioning).

## Test taxonomy

Every spec tags its test functions with one or more markers (registered in
`pyproject.toml` `[tool.pytest.ini_options] markers`) so a run can be sliced
by intent:

| Marker | Meaning |
|---|---|
| `positive` | Happy path — valid input, expected success. |
| `negative` | Invalid input / unauthorized / malformed request — asserts a clean rejection (right status + message), never a 500/crash. |
| `regression` | Pins a specific previously-fixed bug (cite the fix) so it can't silently return. |
| `e2e_flow` | A multi-step user journey across several pages/endpoints (e.g. upload -> scan -> report -> PDF -> delete). |
| `preprod` | Safe to run against a shared pre-production/staging deployment — read-mostly, never mutates a *shared* fixture (scratch data only, always self-cleaning). |
| `smoke` | Fast, minimal-coverage harness sanity check (server up, login works). |

A test can carry more than one marker, e.g. an upload-flow test is both
`e2e_flow` and `positive`.

## Conventions (read before adding a spec)

- **Never mutate a shared fixture.** `fixtures.data.SCANNED[...]` hashes are
  relied on by many specs as read-only, pre-scanned samples. A test that
  needs to create/delete/modify a scan must do so against a **private
  scratch copy** (unique content + `uuid4` suffix, cleaned up in a
  `finally`), never against a `SCANNED[...]` hash. See
  `ui/specs/test_dashboard.py::test_upload_redirects_to_recent_scans` for
  the pattern.
- **Two distinct RBAC denial shapes exist — don't conflate them.** See the
  docstring at the top of `api/client.py`: the API-auth middleware layer
  (`401`/`403` before any view runs) vs. the per-view RBAC decorator layer
  (`401 unauthenticated` / `403 forbidden`) vs. a handful of **legacy**
  views still on Django's classic `@permission_required` (different 403
  envelope again — no `"error"` key, uses `{"status": "denied", ...}`).
  `api/specs/test_scaffold_smoke.py` documents a concrete instance
  (`delete_scan`).
- **Ground every assertion in a real, currently-running server** — read the
  view/template before asserting a count/string, and run the test before
  calling it done. A few pre-existing assertions inherited from `tests_ui/`
  turned out to encode stale assumptions (e.g. a permission-row count that
  no longer matched the fixture) — verified against the live app, not
  guessed.
- **Page Object Model** for UI: put reusable locators/actions in
  `ui/pages/`, keep `ui/specs/*.py` about intent ("assert the roles table
  shows N rows"), not raw selectors, wherever a page is exercised by more
  than one spec.

## Known un-exercisable flows (environment, not gaps in the app)

Same convention as `.coveragerc`'s `omit` — documented exclusions, not
silently-skipped gaps:

- Live dynamic analysis: Frida instrumentation, live API monitor, TLS/pinning
  bypass, logcat streaming, screen mirroring, ADB command exec, root-CA
  install — needs a real attached Android emulator/device.
- iOS Corellium VM / jailbroken-device SSH flows — needs a live Corellium
  instance or physical device.
- Windows PE analysis views — needs a Windows host (BinSkim/BinScope).

These are asserted at the "renders / rejects gracefully without hardware"
level (see `ui/specs/test_general_dynamic.py`), not executed end-to-end.

## Coverage matrix

See `COVERAGE_MATRIX.md` for the page/endpoint -> test-file traceability
table used to track "100%" honestly (100% of the *automatable* surface —
the exclusions above are the same ones `.coveragerc` already documents for
the backend unit-test suite).
