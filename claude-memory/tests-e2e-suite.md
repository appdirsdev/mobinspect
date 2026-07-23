---
name: tests-e2e-suite
description: "The tests_e2e/ Playwright UI + live-API automation suite (added 2026-07-21) — conventions, how to run it, the 3-layer RBAC denial shapes, and the 3 bugs it found (all resolved 2026-07-22)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 5ab6296a-a4ff-4666-ac3f-9b3248f9fe76
---

**`tests_e2e/`** replaced the older `tests_ui/` (fully migrated, `tests_ui/`
deleted) as MobInspect's Playwright UI + live-HTTP API contract suite.
Committed 2026-07-21. 186 passing, 1 documented `xfail`. Full conventions
and a page/endpoint→spec traceability table live in `tests_e2e/README.md`
and `tests_e2e/COVERAGE_MATRIX.md` — read those first, this is a pointer.

**Structure:** `ui/pages/` (Page Object Model) + `ui/specs/`, `api/client.py`
(thin REST wrapper) + `api/schemas/` (jsonschema) + `api/specs/`,
`fixtures/data.py` (single source of truth for already-scanned sample
hashes across every supported format — READ-ONLY, never mutate; any
destructive test must use a private scratch file with a unique-content
suffix instead).

**Taxonomy markers** (registered in root `pyproject.toml`): `positive`,
`negative`, `regression`, `e2e_flow`, `preprod`, `smoke` — every test tags
at least one.

**Run it:** needs a REAL running server (gunicorn, not `runserver` — see
[[release-2026-7]] for the macOS fork-safety + `MOBINSPECT_DEV` gotchas) +
`qcluster` worker. `poetry run pytest tests_e2e/ --browser chromium -q -o
addopts=""` (the `-o addopts=""` is required — root pyproject's addopts is
for the other unit suite).

**RBAC has THREE distinct denial envelopes — a recurring source of wrong
test assertions if assumed to be one shape:**
1. `RestApiAuthMiddleware` (every `/api/*`, runs first): no/bad key → `401
   {"error": "You are unauthorized to make this request."}`; valid key but
   role lacks `api.use` → `403 {"error": "API access not permitted for this
   user."}` (Viewer role has NO `api.use` at all — categorical denial).
2. RBAC `require_permission`/`require_role` decorators (per-view): identified
   user lacking the specific permission → `403 {"error": "forbidden",
   "detail": "..."}`.
3. A few LEGACY views still use Django's classic `@permission_required`
   (`delete_scan`, `suppress_by_rule`) → a THIRD envelope, no `"error"` key
   (`{"status": "denied", ...}`). BUT these are correctly bridged to RBAC —
   see the resolved item below.

**All three bugs this suite found are now RESOLVED (fixed + audited + deployed
to .64, 2026-07-22, commit `0b7c100`):**
- **`/find/` 500-on-every-error — FIXED.** `find.run()` returned a bare
  `dict` (`print_n_send_error_response(..., api=True)`) on every error path →
  Django middleware `AttributeError: 'dict' object has no attribute
  'headers'` → 500. Now returns a real `JsonResponse` (double-encoded to
  match the source-tree client's `JSON.parse(JSON.parse(text)).matches`):
  400 bad/missing hash or search type, 404 missing source dir, clean 500
  catch-all. Also `.get()`-hardened against missing POST fields.
- **`RegisterForm.clean_email` blank-email rejection — FIXED.** Now
  `if email and User.objects.filter(...).exists()` — blank emails allowed
  (Django doesn't treat them as unique); the seeded admin's blank email no
  longer poisons every subsequent blank-email registration.
- **`suppress_by_rule`/`delete_scan` "RBAC vs legacy" — NOT A BUG (test-env
  artifact).** RBAC role → wrapped Django Group IS bridged:
  `add_user_to_group_on_assignment` signal (post_save on RoleAssignment) +
  `create_roles`' `_mirror_rbac_role_groups` (populates the Group's legacy
  `can_suppress`/`can_delete` auth.Permissions — needed because the seed
  MIGRATION sets `role.permissions` via historical models, so the runtime
  m2m sync signal never fires for seeded roles). `entrypoint.sh` runs
  `create_roles` every boot, so production is always synced. The finding was
  from a test/dev DB that ran `migrate` but not `create_roles`. Verified live
  on .64: API User group `can_suppress`=True/`can_delete`=False, Security
  Analyst both True. The tests_e2e top-level conftest now runs `create_roles`
  (autouse session fixture) so the suite matches production, and the
  mis-asserting suppress-denial test was corrected to assert the real allowed
  behavior. **Lesson (see [[verify-dont-trust-agent-reports]]): a subagent's
  confidently-reported "bug" was really a missing setup step — always check
  whether a claimed bug reproduces in a production-faithful environment.**

Audit after the fixes: backend **2384 passed / 100.0% coverage** (12340
stmts, 0 missing); tests_e2e **187 passed / 0 xfailed** (the old `/find/`
strict-xfail is now a passing regression test).

**Fixed during suite-building** (not a live-app bug, was in the new test
harness itself): `MobInspectApiClient.upload_apk()` originally sent a bare
file handle to `requests`' `files=`, omitting the multipart part's
Content-Type — Django then rejected every upload as
`400 "File format not Supported!"` regardless of real bytes. Fixed to set
an explicit Content-Type.
