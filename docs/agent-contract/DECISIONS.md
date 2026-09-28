# Decisions

Answers the contract depends on. **PENDING** rows block every gate that depends on them; an agent
that reaches such a gate stops and records it in `PROGRESS.md`. **DEFAULT** rows are recommendations
the user has not overruled; they may be changed here at any time, and the change is a commit.

| # | Question | Status | Answer |
|---|---|---|---|
| D1 | GPL-3 §5 attribution to the upstream project | DECIDED 2026-09-28 | Keep exactly one attribution: `NOTICE` + the contributor roster in `LICENSE.md`. Nothing else anywhere. |
| D2 | `project-memory/` and `claude-memory/` in git | DECIDED 2026-09-28 | Keep tracked, synced from the auto-memory, allowlisted by the rebrand gate, excluded from the image by `.dockerignore`. |
| D3 | Analyzer-identifier precedence | DEFAULT | Integrations-page `AdbConnection` row wins; `MOBINSPECT_ANALYZER_IDENTIFIER` is the fallback; bare `ANALYZER_IDENTIFIER` accepted with a deprecation warning for one release. |
| D4 | What "password protected" means for the release | DECIDED 2026-09-28 | The distributed artefact is a gpg AES-256 symmetric-encrypted `docker save` archive. The app login (no default credentials, admin password from env/file or generated once) and the generated, persisted Postgres password stay as they are. nginx basic-auth and self-signed TLS are optional follow-ups, not in any DoD. |
| D5 | Pre-stage `frida-server` in the image | DEFAULT | Yes, x86_64 + arm64 with SHA-256 pins (~200 MB). |
| D6 | Version / image tag | DEFAULT | `2026.9.0`; bump `pyproject.toml` from `5.1.0` in W3.13. |
| D7 | Refactor scope for the AdminLTE (`legacy_app.html`) pages | DECIDED 2026-09-28 | Migrate all 15 to `base/app.html`. |
| D8 | Old API path `api/v1/android/mobinspecty` | DEFAULT | Keep as a deprecated alias for one release (`Deprecation` header + warning), then remove. |
| D9 | Build host | DEFAULT | The 192.168.3.65 x86_64 box (previous build server); confirm Docker, ≥60 GB free, and the Granite cache before W3. |
| D10 | AI models baked into the image | DECIDED 2026-09-28 | Both `granite4.1:3b` and `granite4.1:8b`. |
| D11 | Which flows are in scope | DECIDED 2026-09-28 | All four (static lifecycle, Docker first boot, AI enrichment, dynamic analysis) plus merging `fix/docker-allinone-bugs`. |
| D12 | Git history rewrite to purge the old brand and the leaked credentials | DEFERRED | Not part of this contract. Needs a separate explicit go-ahead: it rewrites all commits, breaks both remotes, needs a force-push and credential rotation. Rotate the Gitea password regardless (W1.11). |
| D13 | Rename `mobinspect/MobInspect/` | DECIDED (contract) | No. Recorded in W1.10. |
| D14 | `opensecurity.clipdump` package id inside the bundled `ClipDump.apk` | DEFAULT | Leave and allowlist until the APK is rebuilt and re-signed (separate task). |
| D15 | IP2Location LITE redistribution licence | PENDING (does not block any gate) | See `THIRD-PARTY-LICENCE-RISKS.md`; needs an owner. |
