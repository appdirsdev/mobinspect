---
name: coverage-campaign
description: How to run the full real-execution coverage suite; owned-code scoping now independently verified at 100.0% (2026-07-21)
metadata: 
  node_type: memory
  type: project
  originSessionId: 85e8d82d-ac91-4200-b3a5-995d0479a70e
---

**UPDATE 2026-07-21 — OWNED-CODE COVERAGE: 100.0%** (12337 stmts, 0 missing,
2380 passed / 0 failed; later 12340 stmts / 2384 passed after the 2026-07-22
find.py bugfix + tests, still 100.0%). Independently reproduced on fresh runs
(isolated `POSTGRES_DB` per run, ~11-12 min each) with byte-identical
results — not a one-off fluke. This superseded a same-session false reading
of 98.8%/148-missing that came from exactly the `--reuse-db` corruption
trap described below (a prior agent's run had reused a poisoned test DB;
the "148 missing" and the mass-failure symptom were both artifacts, not
real gaps — always re-verify with a FRESH db before trusting a number, and
don't take a subagent's self-reported number at face value for anything
user-facing/quantitative — rerun it yourself). All 98
`# pragma: no cover` annotations in the codebase were individually audited
this pass and carry specific, verifiable justifications (live network
calls, hardware-locked, Windows-only, provably unreachable) — none exist
to game the number.

**Scope-honesty reminder:** this 100% is 100% of the `.coveragerc`-scoped
subset only. `DynamicAnalyzer/*` (~10k lines), Windows-only views/install
(~1.8k lines), and vendored `androguard4` (~8.6k lines) are excluded from
the denominator for stated, verified reasons — roughly **45% of the
codebase's total lines are excluded**. Never report "100%" without that
caveat; it reads as "100% of the whole app" otherwise.

MobInspect test-coverage campaign. Paths are now `mobinspect/` (post-rebrand, not `mobsf/`).

**Run the full owned-code suite under coverage** (default pytest `testpaths` only covers RBAC+Analytics — the real suite is explicit; every `test_cov_*` + the format E2E driver, minus vendored androguard tests):
```
cd <repo>
set -a; . ./.env.postgres; set +a          # Postgres REQUIRED (127.0.0.1:5433, user admin); no SQLite
export POSTGRES_DB=mi_verify               # unique db => isolated test_<db>, no collision with parallel runs
export MOBINSPECT_JADX_BINARY="$HOME/.MobInspect/tools/jadx/jadx-1.5.0/bin/jadx"
TESTS=$(find mobinspect \( -name "test_cov_*.py" -o -name "test_integration.py" \) | grep -viE "androguard4" | sort)
poetry run coverage run --parallel-mode -m pytest -q --continue-on-collection-errors --reuse-db ${(f)TESTS}
poetry run coverage combine && poetry run coverage report | tail -1
```
- Shell is **zsh**: an unquoted `$VAR` of newline/space-joined paths does NOT word-split. Use zsh array-split `${(f)TESTS}` (or a `mobinspect/**/test_cov_*.py` glob). A plain `$TESTS` mangles all paths into one arg → pytest exit 4 "no tests ran".
- `--import-mode=importlib` (pinned in pyproject addopts) required: two `test_cov_view_source.py` (android+ios) collide otherwise.
- ~2333 tests, ~8 min (in-process `test_integration.py` runs real scans of all 13 `test_files/` samples — apk/xapk/aab/aar/jar/so/src, ipa/dylib/.a/macho/src — under coverage).
- Parallel test-writing agents: give each a unique `POSTGRES_DB` + `COVERAGE_FILE` env → isolated test DB + coverage data, no collision. `poetry run coverage` can break on a pyenv-shim conflict; use `poetry run python -m coverage` as fallback.
- **The authoritative full-suite run MUST use a FRESH test DB — do NOT `--reuse-db`.** A `TransactionTestCase` flushes the migration-seeded RBAC Permission/Role rows (`0003_seed_default_roles`) and doesn't restore them; with `--reuse-db` that flushed state carries into the next run → hundreds of `403 "Insufficient permissions"` failures (every `@require_permission` view, incl. `/api/v1/scan`, which also collapses scan-pipeline module coverage). Same command on a fresh DB = clean 100%. Symptom to recognize: a huge sudden failure count dominated by `403 forbidden` after a prior green run on the same reuse-db.

**OWNED-CODE COVERAGE: 99.2%** (2026-07-18, 12396 stmts, 98 missing, 2333 passed / 0 failed). Up from 84.8% baseline that same session, and from the old 66.9% (which had device/windows/network subsystems still IN the denominator).

**The key change is `.coveragerc` scoping.** It now `omit`s (in BOTH [run] and [report], with stated reasons) the host-locked subsystems so the number reflects "code we own and can run here": `DynamicAnalyzer/*` (device+Frida), `views/windows`+`install/windows` (Windows host), `tools/androguard4/*` (vendored 3rd-party), `VirusTotal.py` (live API), `__main__.py` (server entrypoint). All app formats (Android + iOS + Mach-O/ELF/.a/.so + source zips) ARE in scope and covered.

**Remaining ~98 lines to true 100%** = device-only dynamic-API branches (`api_*_dynamic_analysis`, api_ios_device ~35), confirmed dead code (~25 — several are real bugs to DELETE not cover, see [[review-fixes-release-2026-7]] bug list), VT_ENABLED network branches (~6), and ~30 genuinely-coverable RBAC/misc lines. Network/dead/device lines are handled with documented `# pragma: no cover` (50 added, pragma-only, zero logic change).

Real bugs surfaced by the campaign (NOT auto-fixed): manifest KB placeholder-count TypeError across 6 `exported_provider_*_new` rules (silently empties manifest analysis for matching apps); `suppression.py:349` `['severity']==INFO` list-vs-str always-False; MalwareDomainCheck OFAC plain-name vs ISO-long-name mismatch; `EnqueuedTask.__str__` references missing `name` field; `apk_downloader.try_provider` temp-file leak; `init.first_run` `%`-format-string TypeError; several dead `valid_host`/`legacy_home` branches.
