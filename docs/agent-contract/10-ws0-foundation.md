# W0 — Foundation

Prerequisite for everything else. Nothing user-visible changes; the tree gains the all-in-one image
source, working CI, the rebrand gate, and a recorded baseline.

Branch: `ws/0-foundation` off `release-2026.9`. Gates on exit: G-code, G-rebrand (expected red, count recorded).

## 0.1 Merge `origin/fix/docker-allinone-bugs` — S

`git merge-tree --write-tree release-2026.9 origin/fix/docker-allinone-bugs` reports a clean merge.
The branch brings 7 commits (2026-08-04/05):

- `docker/allinone/{Dockerfile,entrypoint.sh,supervisord.conf,nginx.conf,run-postgres.sh,run-ollama.sh,run-django-init.sh,run-web.sh,run-worker.sh}` — the single-container image.
- root `Dockerfile` — JADX installed in a `RUN` after `COPY . .` with a `test -x` guard (it was never actually baked before: `tools_download.py` ran before the package was importable and the failure was swallowed).
- `scripts/dependencies.sh` — `set -e` and a `uname -m` fallback when `TARGETPLATFORM` is empty (previously shipped no wkhtmltopdf on arm64 hosts).
- `mobinspect/MobInspect/views/api/api_middleware.py` — `_merge_json_body_into_post()` so JSON bodies reach `request.POST` on `/api/v1/*` (was a bogus 422); `test_cov_api_middleware.py`.
- `mobinspect/StaticAnalyzer/views/android/views/manifest_view.py` — `request.GET.get('type', 'apk')` (bare URL was a 500); `test_cov_manifest_view.py`.
- `claude-memory/allinone-docker-build.md` — the build/audit/E2E notes; copy it into `project-memory/` too.

Steps: `git merge --no-ff origin/fix/docker-allinone-bugs` → run the two new `test_cov_*` files → `git push github release-2026.9`.

Acceptance: `ls docker/allinone` lists the 9 files; the 2 new test files pass; push succeeded.

## 0.2 Revive CI — S

Every workflow currently triggers on a branch that does not exist or is stale:

| Workflow | Today | Change |
|---|---|---|
| `.github/workflows/branch-tests.yml` | `release-2026.7, mobinspect, main` | `release-2026.*`, `mobinspect`, `main` |
| `mobinspect-test.yml` (the only lint job) | `master` | `main` + `release-*`; add a `postgres:16` service and `POSTGRES_USER/PASSWORD/HOST/PORT/DB` env — `settings.py:165-185` raises `ImproperlyConfigured` without them |
| `codeql-analysis.yml`, `docker-test.yml`, `docker-latest.yml` | `master` | `main` (+ `release-*` for `docker-test.yml`) |

Add to the test job: `poetry run python manage.py makemigrations --check --dry-run` and `poetry lock --check`.
Add a `rebrand` job that runs `scripts/check-rebrand.sh` (allowed to fail until W1 lands: mark it
`continue-on-error: true` with a comment that W1 flips it to required).

Acceptance: a push to `release-2026.9` starts the test, lint and rebrand jobs; test + lint green.

## 0.3 Rebrand gate — S

`scripts/check-rebrand.sh` and `scripts/rebrand-allowlist.txt` exist (written with this contract).
Add `[testenv:rebrand]` to `tox.ini` that runs the script. Run it once and paste the FAIL summary
into `PROGRESS.md` — that number is W1's starting line (177 residual lines in 29 files on 2026-09-28 with the initial allowlist, of which the rule-file MSTG links are 98 and `.github/SECURITY.md` is 22).

## 0.4 Baseline capture — M

Record in `PROGRESS.md` → "Baseline":

- `poetry run pytest -q` — passed / skipped / failed counts.
- `poetry run pytest tests_e2e -q` — counts (needs a running local stack; note which specs are device-blocked).
- `poetry run python manage.py check` and `makemigrations --check --dry-run` output.
- Golden files: for every fixture in `test_files/` (`android.apk`, `android.aar`, `android_src.zip`, `ios.ipa`, `ios_src.zip`, `windows.appx`, …) run a scan through the API and store `report_json`, `scorecard` and the PDF page count as `tests_e2e/golden/<fixture>.{report.json,scorecard.json,pdf-pages}` (sorted with `jq -S`; commit if the set is under 5 MB, otherwise keep under the scratch dir and record the sha256s). These are the G-golden reference for W4.
- `du -sh mobinspect/static` and `find mobinspect/templates -name '*.html' | wc -l`.

Acceptance: the Baseline section is filled with pasted output, not summaries.
