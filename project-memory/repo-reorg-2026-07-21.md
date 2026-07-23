---
name: repo-reorg-2026-07-21
description: "2026-07-21 repo hygiene/folder pass — what moved, what stayed at root and why, and the self-locating-script gotcha it surfaced"
metadata: 
  node_type: memory
  type: project
  originSessionId: 5ab6296a-a4ff-4666-ac3f-9b3248f9fe76
---

**Root is now down to genuine tool-convention files only**: `manage.py`,
`Dockerfile`, `pyproject.toml`/`poetry.lock`, `tox.ini`, `README.md`,
`LICENSE.md`, `.env.postgres.example`, config dotfiles. Every operational
script now lives in `scripts/`.

**What moved into `scripts/`:** `prod.sh`, `run-mobinspect.sh`, `run.bat`,
`run.sh`, `setup-ubuntu.sh`, `setup.bat`, `setup.sh`, and root `start.sh`
— the last one **renamed to `start-all.sh`** because it collided with a
pre-existing, *different-purpose* `scripts/start.sh` (a simpler dev
launcher already referenced by README/docs — CSS build + migrate + seed +
serve on :8001, vs. the renamed one's full postgres+AVD+qcluster+gunicorn
orchestration). That two-scripts-same-name situation was itself a real
confusion risk, not just a naming quirk.

**Also moved:** `STATE.md` (root) → `docs/STATE.md`, now indexed in
`docs/README.md`.

**The gotcha to remember for any future file-move in this repo:** three of
the moved scripts compute their own directory to locate repo-root files —
`cd "$(dirname "$0")"` — which assumed "my directory == repo root". Moving
them one level deeper into `scripts/` would have silently broken every
relative path inside (`.env.postgres`, `manage.py`, sibling scripts) had
this not been caught and fixed to `cd "$(dirname "$0")/.."`. Always grep a
shell script for `dirname|BASH_SOURCE|SCRIPT_DIR|REPO_(DIR|ROOT)` before
relocating it. Scripts WITHOUT that pattern (bare relative paths like
`scripts/clean.sh`, `manage.py`) are actually fine to move — they already
assumed "invoked from repo root via CWD", which is preserved as long as
callers still do `./scripts/whatever.sh` from repo root (not `cd scripts &&
./whatever.sh`).

**Verification method used (repeat for any future structural move in this
repo):** (1) grep every reference across README/docs/Dockerfile/docker-
compose/CI/deploy *before* moving anything, (2) `bash -n` syntax-check
every touched script, (3) actually exercise the self-location fix by
simulating multiple invocation styles (`bash -c 'cd "$(dirname "$path")/.."
&& pwd'` from root, from a subdir, with an absolute path), (4) live smoke-
test at least one moved script if it's cheap and side-effect-free (did this
for `scripts/run.sh` — started gunicorn on a scratch port, curled 200, tore
down), (5) rerun the full `tests_e2e` suite to confirm the app itself is
unaffected. Do NOT just move-and-hope — the user explicitly requires
"nothing broken, everything working end-to-end" for any reorg in this repo.

**Deliberately left untouched:** `claude-memory/`/`project-memory/`
(historical dev-session notes; consolidating is a content decision, could
also be depended on by external tooling at those exact paths, out of scope
for a hygiene pass) and all root scripts that ARE genuinely referenced by
name in active docs (none — turned out none of the 8 moved scripts were
referenced by README, docs/09-development-setup.md, Dockerfile, CI, or
deploy/, which is exactly what made the move safe).
