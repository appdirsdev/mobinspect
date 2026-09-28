# Changelog

All notable changes to MobInspect are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the release-branch
calendar scheme (`YYYY.M`) until the image tag scheme in `docs/agent-contract/DECISIONS.md` (D6) lands.

## [Unreleased] — release-2026.9

### Added
- Agent contract under `docs/agent-contract/` — binding workstream specifications, hard rules,
  gates, decisions ledger and progress ledger for the rebrand completion, broken-flow fixes,
  single-container release and refactor work. Mirrored for automatic loading in
  `.claude/rules/agent-contract.md`.
- `scripts/check-rebrand.sh` with `scripts/rebrand-allowlist.txt` — the gate that fails while any
  upstream-brand residue remains outside the documented allowlist.
- `docs/agent-contract/THIRD-PARTY-LICENCE-RISKS.md` — bundled data and tool licences that need an owner.

### Removed
- `test_files/ios_swift_src.zip` (73 MB, unused fixture).

### Known issues (tracked in the contract)
- Invented identifiers (`mobinspecty`, `MobInspect_API30`) and dead `github.com/MobInspect/…` links
  remain until W1; CI workflows trigger on branches that do not exist until W0.2; the in-repo
  `docker/docker-compose.yml` lags the deployed stack until W2.g.

## [2026.8] — 2026-07-23
- Tip of `release-2026.8`: memory sync and credential redaction; `/find/` error handling and
  `RegisterForm` blank-email fixes; Tailwind build baked into the Docker image; test suites and
  session notes excluded from the Docker build context; root scripts folded into `scripts/`.

## [2026.7] — 2026-07-15
- Granite LLM enrichment (4-stage pipeline, AI dashboard, integrations page), design-system
  redesign, in-app Help page, live scan progress, RBAC/audit fixes, PostgreSQL-only database.

Earlier history: `git log --first-parent mobinspect`.
