---
name: agent-contract
description: "The binding agent contract (docs/agent-contract/) written 2026-09-28 — read it BEFORE any work; the 4 workstreams, execution order, user decisions D1–D15, the rebrand gate script, what the earlier blind-sed rebrand broke, where the all-in-one image lives"
metadata:
  node_type: memory
  type: project
  originSessionId: 56c7ac5d-553a-48fb-823c-c892882744eb
  modified: 2026-09-28T18:27:34.795Z
---

**Every agent run on MobInspect from 2026-09-28 is governed by `docs/agent-contract/00-contract.md`** (mirrored in `.claude/rules/agent-contract.md`, which auto-loads). Read it → the workstream file → the tail of `docs/agent-contract/PROGRESS.md`, then re-run the last gate before continuing. The 12 hard rules include: preserve behaviour (byte-identical `<script>` blocks), never fabricate data, verify before claiming, re-verify subagent numbers, **image tests not hot-patched-container tests**, honest coverage, no credit lines, `{% comment %}` only, one workstream per branch, stop at a gate you cannot pass.

**Why:** the user asked (2026-09-28) for "a solid contract for agents" covering (1) full refactor/optimise, (2) complete rebrand with zero upstream identity, (3) fix the broken flows (all four: upload→scan→report→PDF, Docker first boot, AI enrichment, dynamic analysis) + merge `origin/fix/docker-allinone-bugs`, (4) a single all-in-one Docker production image (granite4.1:3b + 8b baked) shipped as a **gpg-encrypted `docker save` archive** (that is what "password protected" means — D4). This session delivered the contract + plan only; execution is later runs.

**Execution order (do not reorder without re-reading the rationale):** W0 foundation → W1 rebrand → W2 (g,f,a,b,c,d,j) → W3 all-in-one release → W2 (e,h,i,k) → W4 refactor. The image is `COPY . .`, so rebrand + runtime flow fixes must precede the image cut; refactor is last and gated by golden `report_json`/`scorecard` files captured in W0.4.

**Branch:** everything lands on `release-2026.9` (created 2026-09-28 from `feature/granite-llm-integration` tip `752419b`, pushed to `github`) via `ws/<n>-<slug>` branches. Push to `github` only; `origin` Gitea is unreachable and its URL embeds a plaintext password (operator must rotate — W1.11).

**Key facts the contract encodes (so nobody re-derives them):**
- Literal `mobsf` is gone from code; the earlier rename was a **blind sed** that produced `mobinspecty`/`is_mobinspectyied`/`MobInspect_API30`, 98 rules-YAML MSTG links to a non-existent `github.com/MobInspect/owasp-mstg`, upstream GHSA advisories + Slack invite relabelled as ours in `.github/`, a `.gitmodules` submodule to a non-existent repo, and nonsense docs ("MobInspect → MobInspect"). W1 reverses each class. `scripts/check-rebrand.sh` + `scripts/rebrand-allowlist.txt` is the gate (231 residual lines / 40 files on 2026-09-28 before the allowlist).
- `origin/fix/docker-allinone-bugs` (7 commits, Aug 2026) already holds `docker/allinone/` (supervisord + Postgres + Ollama + nginx + web + worker; models via `--build-context ollama-cache=~/.ollama/models`), the root-Dockerfile JADX-after-COPY fix, `dependencies.sh` `set -e`, JSON-body API middleware, `manifest_view` default — merges CLEAN. W0.1 merges it; W3 builds on it. Its notes are in `project-memory/allinone-docker-build.md` after the merge.
- Build host must be x86_64 Linux + Docker + ≥60 GB + Granite cache (D9: the .65 box). This Mac cannot build (no Docker, 4.7 GB free).
- Decisions: D1 keep ONE GPL-3 attribution (`NOTICE` + LICENSE roster); D2 keep `project-memory/`+`claude-memory/` tracked, synced, allowlisted; D7 migrate ALL 15 `legacy_app.html` pages in W4; D12 history rewrite deferred; D13 `mobinspect/MobInspect/` dir not renamed; D15 IP2Location LITE licence PENDING (non-blocking).

**How to apply:** when asked to "continue", "do W1", "build the image", etc., open the contract files first and follow the task tables — they carry file:line references from the 2026-09-28 exploration. Update `PROGRESS.md` and this memory (then sync both memory dirs in the repo) at every hand-off.
