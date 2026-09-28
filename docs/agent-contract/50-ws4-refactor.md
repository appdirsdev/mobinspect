# W4 — Refactor and optimise

Runs last. Every phase must prove it changed nothing the user can observe: the golden files from
W0.4 (`report_json`, `scorecard`, PDF page count for every `test_files/*`) diff empty, the pytest
count does not drop, `tests_e2e` passes, G-rebrand and G-code stay green. A phase that cannot show
that is reverted, not argued for.

Branch: `ws/4-<phase>` per phase. Gates: G-code, G-e2e, G-golden per phase; G-image once at the end.

## 4.1 Tooling — M

Replace flake8 + autopep8 (`tox.ini [testenv:lint]` currently *mutates* code with `autopep8 --in-place`
and has never run in CI) with `ruff`: rules `E, F, I, B, UP, C901`, `max-complexity = 25` to start and
ratchet down; config in `pyproject.toml`; `ruff check` + `ruff format --check` in the CI lint job on
`release-*` and `main`. Apply only the safe auto-fixes (`I`, `UP`) in a dedicated commit that is
reviewed as a diff, not trusted.

## 4.2 Environment parsing — M

`mobinspect/MobInspect/init.py` has `env()`; `settings.py` still has 33 raw `os.getenv` calls and 44 ad-hoc
boolean idioms (`== '1'`, `in ('1','true',…)`). Add `env_bool()`, `env_int()`, `env_list()` beside
`env()` and migrate settings, init (5), utils (4). Proof: `test_cov_init.py` + settings tests; the app boots
with the same `.env.postgres`.

## 4.3 Response helpers — L

`print_n_send_error_response` (107 sites, returns dict or `HttpResponse`), `make_api_response` (248),
`send_response` (149) and 19 raw `HttpResponse(json.dumps(...))` become
`mobinspect/MobInspect/views/responses.py` with `api_ok`, `api_error`, `html_error`; the 38 copies of the
`if not is_md5(...)` guard become a `@require_md5` decorator. Migrate module by module in separate
commits. Proof: `tests_e2e` API + UI suites; error-page snapshots.

## 4.4 Dead code, duplicated assets, the AdminLTE pages — L

- Delete: `mobinspect/templates/base/base_layout.html` (referenced only in a comment), `mobinspect/static/chartjs/` (0 templates), `static/jqueryknob/`, `static/landing/`, the AdminLTE DataTables copies (standardise on `datatables/js/datatables.combined.min.js`), the duplicate Chart.js v2, `six` and `bcrypt` from `pyproject.toml`.
- Shared JS: `function counter(` is defined in 21 templates, `dynamic_loader` in 8, `escapeHtml` and `animateBullet` in 7, `stop_loader` in 5 → one `static/mobinspect/js/ui.js` loaded from `base/app.html`; remove the inline copies with a `<script>`-block diff per template (the method from the 2026-07 template sweep).
- Shared partials for the four report templates (`android_binary_analysis.html` shares 515 of 915 substantive lines with `ios_binary_analysis.html`; the source pair shares 332/644) and the PDF pair.
- **Migrate all 15 templates that still extend `base/legacy_app.html` to `base/app.html`** (D7). Order: the four report pages, the dynamic analyzer pages, then the rest. Each page gets a Playwright spec before the change and the same spec after; severity colours stay semantic (the failure mode most likely to slip is a badge recoloured as a "generic accent").

Proof: Playwright suite count ≥ baseline; `du -sh mobinspect/static` down ≥ 6 MB; `git grep -l legacy_app.html mobinspect/templates` empty.

## 4.5 Hot functions — L

`mobinspect/StaticAnalyzer/views/android/manifest_analysis.py:212` `manifest_analysis` is 655 lines → a
table of rule entries evaluated by small functions; `ios/app_transport_security.py:1
check_transport_security` (240), `android/network_security.py:58 analysis` (238), `home.py:196 index` (159)
similarly. Output must be byte-identical: G-golden is the gate, plus one unit test per extracted rule.

## 4.6 ORM — M

`mobinspect/MobInspect/views/authorization.py:197` issues one query per role and permission → a single
`values_list`; audit every `.only()` and add `select_related` where the template dereferences a
relation (the codebase has 4 uses today). Proof: `assertNumQueries` on the recent, tasks, and RBAC pages.

## 4.7 Settings import side effects — M

`settings.py:65` calls `first_run()` — `makemigrations`, `migrate` and a JADX download thread — during
settings import. Move that into `manage.py init_home`, called by both entrypoints and
`scripts/start-common.sh`; settings only creates directories and reads the secret. Proof: importing
settings in a shell triggers no DB or network activity; boot scripts behave as before.

## 4.8 Timeouts — M

29 non-Popen `subprocess` calls have no `timeout=` (`shared_func.py` 5, `ios/device/connect.py` 4,
`android/environment.py` 4, …); `install/windows/setup.py:78,149,234,266` `urlopen` without timeout;
`corellium_apis.py:544` reads a whole IPA into memory for an untimed `requests.put`. Bounds come from
one settings table. Proof: unit tests with sleeping fakes.

## 4.9 Dependencies — S

`pyproject.toml` has `django = ">=3.1.5"` while the lock has 6.0.3; set `django = "^6.0"`,
`python = "^3.13"`, and tighten the `>=` pins to the lock's majors; Docker installs from the lock
(W2.g); CI runs `poetry lock --check`. Proof: clean install; full suite green; `docker-test.yml`
builds amd64 and arm64.

## Definition of Done

G-golden diff empty for every fixture; `ruff check` and `ruff format --check` clean; no function over
150 lines outside vendored `androguard4` (`python - <<'EOF' … ast …` script committed as
`scripts/long-functions.py`); `mobinspect/static` at least 6 MB smaller than baseline; Playwright and
pytest counts at or above baseline; zero templates extend `legacy_app.html`; G-image re-run green.
