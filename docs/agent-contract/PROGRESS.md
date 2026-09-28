# Progress ledger

Tick a box only with the commit hash and a pasted excerpt of the gate output that proves it.
Session log entries go at the bottom, newest last. Nothing here is assumed true by a later session
until the gate is re-run.

## Baseline (filled by W0.4)

```
pytest:            (pending)
tests_e2e:         (pending)
manage.py check:   (pending)
makemigrations --check --dry-run: (pending)
check-rebrand.sh:  FAIL (177 residual lines in 29 files) — 2026-09-28, with the initial allowlist; 231 raw hits before it
du -sh mobinspect/static: (pending)
golden files:      (pending) tests_e2e/golden/<fixture>.{report.json,scorecard.json,pdf-pages}
```

## W0 — Foundation
- [ ] 0.1 `fix/docker-allinone-bugs` merged into `release-2026.9`, pushed; `docker/allinone/` present; 2 new test files pass
- [ ] 0.2 CI triggers fixed; Postgres service in `mobinspect-test.yml`; `makemigrations --check` + `poetry lock --check` steps; rebrand job (continue-on-error until W1)
- [ ] 0.3 `tox -e rebrand` added; first FAIL summary pasted into Baseline
- [ ] 0.4 Baseline section filled with pasted output; golden files captured

## W1 — Rebrand completion
- [ ] 1.1 `mobinspecty` family → `prepare_device`; alias route answers identically; e2e dynamic spec green
- [ ] 1.2 one AVD name (`MobInspect_AVD`)
- [ ] 1.3 98 MSTG links rewritten; curl loop prints nothing
- [ ] 1.4 dead URLs removed (`macho.py`, `dynamic.html`, `manage.py`, `install/windows/readme.md`)
- [ ] 1.5 `.github/` community files rewritten/deleted
- [ ] 1.6 submodule removed; `tests.py` points at root `test_files/`
- [ ] 1.7 docs and comments de-garbled; `07-rebrand-checklist.md` rewritten as the Rebrand record
- [ ] 1.8 `NOTICE` added (D1)
- [ ] 1.11 operator: Gitea password rotated, remote URL cleaned
- [ ] **Gate:** `scripts/check-rebrand.sh` → `REBRAND GATE: PASS`; CI rebrand job flipped to required

## W2 — Broken flows
- [ ] a  air-gap: `MOBINSPECT_OFFLINE`; bounded `update_local_db`, `tools_download`, DNS, `ServerProxy`; no `setdefaulttimeout`; offline scan matches golden
- [ ] b  stuck states: `sweep_stale_tasks`; `AIEnrichment.UPDATED_AT` + retry window
- [ ] c  one canonical `MOBINSPECT_ANALYZER_IDENTIFIER` (D3 precedence); deploy files updated
- [ ] d  adb timeouts (`system_check`, `adb devices`)
- [ ] e  API-reachable error paths return JSON
- [ ] f  AI: `keep_alive` coercion; pinned-IP enclave check; `last_status` on failure; env-only config; `granite4.1` defaults; `seed_ai_integrations`
- [ ] g  first boot: `migrate` only; `seed_rbac` + `create_roles` + `bootstrap_admin` (+Administrator) + `seed_ai_integrations`; compose mirrors .64; nginx 550M; lock-based installs
- [ ] h  query counts (`ICON_PATH`, `list_tasks`, `page_size` cap)
- [ ] i  `restore.sh` → `pg_restore`; drop-in dirs renamed; `ExecStartPre` migrate
- [ ] j  `STORAGES`; `USE_L10N`/`TEMPLATE_DEBUG` gone; ENGINE modernised
- [ ] k  dynamic-analysis DoD recorded (env-blocked or AVD smoke)
- [ ] **Gate:** `tests_e2e/flows/{static_flow,ai_flow,persist,password,dynamic_boundary}.sh` pass against a fresh container

## W3 — All-in-one release
- [ ] 3.1 reproducible build (lock, pinned installers)
- [ ] 3.2 Postgres password reconciliation on boot
- [ ] 3.3 `MOBINSPECT_ADMIN_PASSWORD_FILE`; generated password banner
- [ ] 3.6 rate limits keyed on `X-Real-IP`
- [ ] 3.7 `ALLOWED_HOSTS` ergonomics + fail-fast banner
- [ ] 3.8 `/tests/` behind auth
- [ ] 3.9 `healthcheck.sh` covers all five processes; `supervisorctl` works
- [ ] 3.10 disk guard + `prune_scans`
- [ ] 3.11 offline assets; `MOBINSPECT_OFFLINE=1` default
- [ ] 3.12 Frida pre-staged with SHA pins (D5)
- [ ] 3.13 `scripts/build-allinone.sh`; version `2026.9.0` (D6)
- [ ] 3.14 `scripts/release-allinone.sh` → `.tar.gz` + `.sha256` + `.tar.gz.gpg`
- [ ] 3.15 `docs/allinone-deploy.md`
- [ ] 3.16 fresh-image E2E checklist with evidence
- [ ] 3.17 `docker-allinone.yml` dispatch build; shared `install-jadx.sh`
- [ ] **Gate:** G-image end to end from a fresh clone on the build host; encrypted archive round-trips on a clean host

## W4 — Refactor and optimise
- [ ] 4.1 ruff replaces flake8/autopep8; CI lint runs
- [ ] 4.2 env parsing unified
- [ ] 4.3 response helpers unified; `@require_md5`
- [ ] 4.4 dead assets removed; shared `ui.js`; shared report partials; all 15 `legacy_app.html` pages migrated (D7)
- [ ] 4.5 hot functions split; golden identical
- [ ] 4.6 ORM query counts
- [ ] 4.7 `first_run()` out of settings import
- [ ] 4.8 timeouts on every subprocess/urlopen call
- [ ] 4.9 dependency pins tightened; `poetry lock --check` in CI
- [ ] **Gate:** G-golden empty; ruff clean; no function >150 lines; static ≥6 MB smaller; suites ≥ baseline; G-image re-run green

## Session log

### 2026-09-28 — contract written
- Branch tip: `release-2026.9` (contract commit).
- Done: exploration of the tree, `fix/docker-allinone-bugs`, deployment notes; user decisions D1, D2, D4, D7, D10, D11 recorded; contract files, rules mirror, `scripts/check-rebrand.sh` + allowlist, `CHANGELOG.md`; `release-2026.9` created from `feature/granite-llm-integration` and pushed.
- Half-done: nothing.
- Next command (W0.1): `git checkout -b ws/0-foundation release-2026.9 && git merge --no-ff origin/fix/docker-allinone-bugs`
