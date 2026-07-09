# MobInspect UI end-to-end tests (Playwright)

Browser-driven tests that exercise the redesigned UI against a **running**
MobInspect server. They are deliberately **outside** the pyproject `testpaths`,
so the normal unit suite (`scripts/run-tests.sh`) never collects them — run them
explicitly.

## One-time setup

```bash
poetry run pip install pytest-playwright playwright
poetry run playwright install chromium        # uses cached browser if present
```

## Run

Start a server (admin/admin), then:

```bash
# defaults: MOBINSPECT_UI_BASE=http://127.0.0.1:8000, admin/admin
poetry run pytest tests_ui/ --browser chromium -q -o addopts=""
```

Override target/creds via env: `MOBINSPECT_UI_BASE`,
`MOBINSPECT_ADMIN_USERNAME`, `MOBINSPECT_ADMIN_PASSWORD`.

## Layout

| File | Covers |
|------|--------|
| `test_smoke.py` | login + home render (harness sanity) |
| `test_dashboard.py` | creative home: animated counters, upload zone wiring, quick actions, recent activity |
| `test_integrations.py` | 4 fixed integration cards, Save & Test, inline Test, status pills |
| `test_rbac.py` | roles / role form / api-keys / audit / permissions / users / register |
| `test_analytics.py` | KPI widgets + Chart.js canvases render |
| `test_report.py` | Android report tabs/sections, AppSec dashboard, AI dashboard watermark |
| `test_general_dynamic.py` | about / api_docs / recent / dynamic-analysis landing |

`conftest.py` provides `admin_page` — a Playwright `Page` already authenticated
as admin (session-scoped `storage_state`, so login happens once per run).

## Known un-exercisable flows (environment, not gaps in the app)

These require a real attached Android emulator / iOS device or are destructive,
so they assert that controls **render** rather than executing them:

- Live dynamic analysis: Frida instrumentation, live API monitor, TLS/pinning
  bypass, logcat streaming, screen mirroring, ADB command exec, root-CA install.
- Device provisioning ("Prepare runtime"), Install+Analyze on-device actions.
- iOS Corellium VM / jailbroken-device SSH flows.
- Real file upload (would create a live scan) and RBAC create/delete/revoke
  (destructive) — form + validation rendering is asserted instead.
- "Connected" status on Integration Save/Test needs a real adb server + a live
  local LLM endpoint; tests assert against the full status set.
