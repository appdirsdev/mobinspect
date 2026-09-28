# MobInspect Agent Contract

This directory is the binding specification for every agent run (workflow, subagent, or human) that
touches MobInspect from 2026-09-28 onward. It exists because earlier passes shipped an image that
predated its own fixes, a blind find-and-replace left invented identifiers and dead links in
production code, and session knowledge lived only in chat. Nothing here is advisory: the gates in
§5 decide whether work is done.

Files:

| File | Purpose |
|---|---|
| `00-contract.md` | this file: scope, order, hard rules, Definition of Done, gates, environment facts, hand-off |
| `10-ws0-foundation.md` | W0: merge the all-in-one fix branch, revive CI, install the rebrand gate, capture baselines |
| `20-ws1-rebrand.md` | W1: finish the rebrand and reverse the find-and-replace damage |
| `30-ws2-broken-flows.md` | W2: upload→scan→report→PDF, Docker first boot, AI enrichment, dynamic analysis, plus the stall/stuck-state/naming bugs |
| `40-ws3-allinone-release.md` | W3: the single-container production image and its encrypted release archive |
| `50-ws4-refactor.md` | W4: refactor and optimisation, functionality-preserving, runs last |
| `DECISIONS.md` | the user's answers; a PENDING row blocks every gate that depends on it |
| `PROGRESS.md` | the checkbox ledger and session hand-off log |
| `THIRD-PARTY-LICENCE-RISKS.md` | bundled data/tool licences that need an owner |

## 1. Scope

Four workstreams, one prerequisite:

- **W0 Foundation** — merge `origin/fix/docker-allinone-bugs` (7 commits, clean merge), fix CI triggers that point at branches which do not exist, add `scripts/check-rebrand.sh`, record baselines.
- **W1 Rebrand completion** — zero upstream identity in shipped code, templates, rules, docs, CI; exactly one GPL-3 attribution kept (D1).
- **W2 Broken flows** — all four flows the user named, plus the concrete defects found in code (air-gap stall, stuck task/AI states, three-way analyzer-identifier naming, runtime `makemigrations`, stale compose, SQLite restore script, Django 6 `STORAGES`).
- **W3 All-in-one release** — `docker/allinone/` (Postgres + Ollama with `granite4.1:3b` and `granite4.1:8b` baked + gunicorn + qcluster + nginx under supervisord) built from a fresh clone on the x86_64 build host, verified from a fresh container, shipped as a gpg-encrypted `docker save` archive (D4).
- **W4 Refactor + optimise** — tooling, env parsing, response helpers, dead assets, shared partials, the 15 AdminLTE pages (D7), hot functions, ORM, timeouts, dependency pins; every phase proven behaviour-preserving by golden files.

Out of scope (recorded so nobody re-litigates it): renaming the `mobinspect/MobInspect/` project directory; rewriting git history; multi-tenancy; hosting the Android emulator inside the container; nginx basic-auth and self-signed TLS (optional follow-ups listed in W3, not part of any DoD).

## 2. Order of execution

```
W0 → W1 → W2 (g, f, a, b, c, d, j) → W3 → W2 (e, h, i, k) → W4
```

The image is a `COPY . .` of the tree: anything that lands after the image is cut forces a rebuild
and a fresh 16 GB export. So the rebrand (mechanical, gated) and the runtime-behaviour flow fixes
go in before W3; the remaining W2 items are safe post-release; W4 is the largest and riskiest and is
last on purpose, with the golden files from W0 and the shipped image as its stable reference.

## 3. Hard rules

These are mirrored verbatim in `.claude/rules/agent-contract.md` so they load in every session.

1. **Preserve behaviour.** Template edits leave existing `<script>` blocks byte-identical unless the workstream file names that script; chart datasets/labels/types, `{% url %}`, CSRF, form field names/ids, DataTable/EventSource/Alpine/CodeMirror hooks stay intact; diff against a captured baseline before claiming done.
2. **Never fabricate data.** No mock metrics, placeholder counts, or invented deltas. A page with nothing real to show shows nothing.
3. **Verify before claiming.** Every "done / fixed / passing" statement is preceded by the actual command and its pasted output. No output, no claim.
4. **Re-verify subagent reports independently.** A number or "all green" from a subagent is a hypothesis until the coordinator reruns the command.
5. **Image tests, not container tests.** Any Docker claim comes from a fresh container created from the built image (`docker rm` + `docker run`), never from a hot-patched running container. (2026-08-05: two shipped images lacked fixes that "E2E green" had only ever exercised in a hot-patched container.)
6. **Honest coverage.** Report the real number; the known ceiling is about 67% (device/Windows/network-locked paths). Never delete or skip tests to raise it.
7. **Security invariants.** AI-generated text is never rendered with `|safe`; the deterministic `security_score` is never AI-written; severity colours are semantic-only; no new unauthenticated routes; `/tests/` gets auth.
8. **Credentials.** `admin/admin` and `.env.postgres` are local-only and never committed; no default credentials in any image; secrets only via env, `_FILE`, or generated-and-persisted.
9. **No credit lines.** No `Co-Authored-By`, "Generated with", or tool attribution in commits, code, docs, or release notes.
10. **Template comments use `{% comment %}`**, never HTML comments containing template syntax.
11. **One workstream per branch/PR; no drive-by refactors** inside rebrand or flow-fix commits.
12. **Stop at a gate you cannot pass.** Record the blocker in `PROGRESS.md` and end the session; never bypass (`--no-verify`, skipped tests, `force`).

## 4. Definition of Done

**Global:** every gate in §5 that applies to the workstream is green on the branch tip; the
workstream's boxes in `PROGRESS.md` are ticked with the commit hash and a pasted gate excerpt;
`DECISIONS.md` has no PENDING row the workstream depended on; the credit-line grep in G-code is empty.

Per workstream (detail in each file):

- **W0** — fix branch merged into `release-2026.9`; CI runs on a push to `release-2026.9`; `scripts/check-rebrand.sh` installed (red is expected until W1); baseline numbers and golden files recorded.
- **W1** — `scripts/check-rebrand.sh` exits 0; `api/v1/android/mobinspecty` and its replacement return identical bodies; the dynamic e2e spec passes; docs read as prose.
- **W2** — `tests_e2e/flows/{static_flow,ai_flow,persist,password,dynamic_boundary}.sh` committed and passing against a fresh container; blackholed-IP unit tests prove every network call returns within its bound; `MOBINSPECT_OFFLINE=1` scan of `test_files/android.apk` completes; one canonical `MOBINSPECT_ANALYZER_IDENTIFIER`; restore script is Postgres; CI triggers match real branches.
- **W3** — G-image passes end to end from a fresh clone on the build host; the encrypted archive decrypts, `docker load`s, and boots healthy on a clean target with only `MOBINSPECT_ADMIN_PASSWORD` and `MOBINSPECT_ALLOWED_HOSTS`.
- **W4** — G-golden diff empty; `ruff` clean; no function over 150 lines outside vendored `androguard4`; `mobinspect/static` at least 6 MB smaller; Playwright count at or above baseline; zero templates extend `legacy_app.html`.

## 5. Gates

Agents run these and paste the final lines into `PROGRESS.md` under the gate heading.

**G-code — every PR**

```
poetry run python manage.py check
poetry run python manage.py makemigrations --check --dry-run
poetry run pytest -q                       # paste "N passed, M skipped"
poetry run python manage.py shell -c "import mobinspect.StaticAnalyzer.views.android.static_analyzer; \
  from django.template.loader import get_template; import pathlib; \
  [get_template(str(p.relative_to('mobinspect/templates'))) for p in pathlib.Path('mobinspect/templates').rglob('*.html')]"
git grep -nE 'Co-Authored-By|Generated with' -- . ':!docs/agent-contract' ':!.claude/rules' && exit 1 || true
```

**G-rebrand** — `scripts/check-rebrand.sh` exits 0. It greps tracked text files for the upstream
brand, the invented identifiers (`mobinspecty`, `MobInspect_API30`), and the dead URL families
(`github.com/MobInspect/`, `mobinspect.github.io`, the Slack invite), then subtracts lines that match
`scripts/rebrand-allowlist.txt` (`path-regex:line-regex`). New allowlist rules need a reason on the
line above and, when they keep the old name in a shipped file, a row in `DECISIONS.md`.

**G-e2e** — `poetry run pytest tests_e2e -q` against a local stack, plus `tests_e2e/flows/*.sh`
against the container.

**G-image — build host only, never on a laptop**

```
git clone --depth 1 -b release-2026.9 https://github.com/appdirsdev/mobinspect.git mi-build && cd mi-build
docker buildx build --platform linux/amd64 -f docker/allinone/Dockerfile \
  --build-context ollama-cache=$HOME/.ollama/models -t mobinspect-allinone:<ver> .
docker run -d --name mi-verify -p 18080:80 \
  -v mi_pg:/var/lib/postgresql/data -v mi_home:/home/mobinspect/.MobInspect -v mi_ollama:/usr/share/ollama/.ollama \
  -e MOBINSPECT_ADMIN_PASSWORD=<throwaway> -e MOBINSPECT_ALLOWED_HOSTS=localhost,127.0.0.1,<host-ip> -e MOBINSPECT_PORT=80 \
  mobinspect-allinone:<ver>
until [ "$(docker inspect -f '{{.State.Health.Status}}' mi-verify)" = healthy ]; do sleep 5; done
docker exec mi-verify nginx -T | grep client_max_body_size                                   # 550M
docker exec mi-verify test -x /home/mobinspect/.MobInspect/tools/jadx/jadx-1.5.0/bin/jadx
docker exec mi-verify curl -sf http://127.0.0.1:11434/api/tags | grep -c 'granite4.1'          # 2
tests_e2e/flows/static_flow.sh   # login → upload test_files/android.apk → poll tasks → report_json → download_pdf (%PDF)
tests_e2e/flows/ai_flow.sh       # AIEnrichment STATUS=done → /ai_dashboard/<md5>/ 200
tests_e2e/flows/persist.sh       # docker rm -f + docker run with the same volumes → scan still listed, apk on disk
tests_e2e/flows/password.sh      # no default creds; GET / → 302 /login; wrong pw re-renders; /healthz public; /tests/ → 302/403
scripts/release-allinone.sh <ver>                                                             # tar.gz + .sha256 + .tar.gz.gpg
gzip -t mobinspect-allinone-<ver>-amd64.tar.gz && sha256sum -c mobinspect-allinone-<ver>-amd64.tar.gz.sha256
gpg --decrypt mobinspect-allinone-<ver>-amd64.tar.gz.gpg | gunzip -c | docker load           # round-trip on a clean host
```

**G-golden — W4 only.** `report_json`, `scorecard` JSON and PDF page count for every file in
`test_files/`, captured in W0.4, `jq -S`-diffed after each refactor phase; the diff must be empty
unless the workstream file waives a named key.

## 6. Environment facts

- **Remotes.** `github` = `github.com/appdirsdev/mobinspect` (reachable, the only push target). `origin` = a Gitea box at `192.168.3.244:3000`, unreachable from most networks; its URL embeds a plaintext password that the operator must rotate and remove (`git remote set-url origin <url-without-creds>`). Never paste that URL anywhere.
- **Branch.** All work lands on `release-2026.9` through short-lived `ws/<n>-<slug>` branches, one PR per workstream slice, merged without squash so bisect works.
- **Build host.** The all-in-one image needs an x86_64 Linux host with Docker, ≥60 GB free, and `~/.ollama/models` already holding `granite4.1:3b` and `granite4.1:8b` (pull once while online). The 192.168.3.65 box served as build server before (D9). A developer laptop is not a build host: the one used to write this contract has no Docker and 4.7 GB free.
- **Deployed reality.** The live stack is the multi-container compose on 192.168.3.64 (`~/mobinspect-deploy/`, with an `ollama` service and `x-mi-env` that the in-repo `docker/docker-compose.yml` does not have yet — W2.g fixes that). 192.168.3.65's systemd install is stopped.
- **Local dev.** Postgres is mandatory (`settings.py:165-185`; no SQLite fallback). Local role/db `admin/admin` on port 5433 via the untracked `.env.postgres`. `manage.py runserver` is blocked unless `MOBINSPECT_DEV=1`; on macOS gunicorn needs `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`; async scans need `manage.py qcluster` running.
- **Suites.** `scripts/run-tests.sh` (pytest, needs Postgres); `tests_e2e/` (Playwright UI + API, `poetry run pytest tests_e2e -q`); llm package has ~419 tests; full suite was 944 passed / 2 skipped at the last recorded run — W0.4 re-establishes the number.
- **Session memory.** `project-memory/` and `claude-memory/` are synced copies of the auto-memory under `~/.claude/projects/<repo>/memory/`. They are tracked (D2), excluded from the image by `.dockerignore`, and allowlisted by the rebrand gate. Keep them in sync when you sync anything else.

## 7. Working model and hand-off

- **Commits.** One logical change each; imperative subject; body says why; no attribution trailers. Mechanical rebrand edits are split by category (identifiers / links / docs / `.github`).
- **Cadence.** G-code before every push; G-e2e per PR; G-image at W3 and once more after W4.
- **Progress.** `PROGRESS.md` mirrors every DoD bullet as a checkbox; tick with the commit hash and a pasted gate excerpt. The Session log at the bottom gets one entry per session: date, branch tip, what finished, what is half-done, the exact next command.
- **Hand-off.** At roughly 70% context or at session end: write the Session-log entry, push, stop. The next session reads this file → the workstream file → the tail of `PROGRESS.md`, then reruns the last gate before continuing. Nothing is assumed to still be true from a previous session until it is re-run.
- **Escalation.** A gate that depends on a PENDING decision, a build host that is not reachable, or a suite that cannot run stops the workstream; it is recorded, not worked around.
