# 07 — Rebrand record

This is the historical record of turning the upstream project (Mobile Security Framework, "MobSF")
into MobInspect. It is the one document, together with `LICENSE.md` and `NOTICE`, that may name the
upstream project; `scripts/rebrand-allowlist.txt` allows it for that reason.

The binding, checkable statement of "what is left" is `scripts/check-rebrand.sh`. If it exits 0,
the rebrand is complete.

## What was renamed (pass 1–4, June–July 2026)

| Area | Before | After |
|---|---|---|
| Python package | `mobsf/`, `mobsf.MobSF` | `mobinspect/`, `mobinspect.MobInspect` |
| Environment variables | `MOBSF_*` | `MOBINSPECT_*` (no compatibility shim; `init.env()` ignores legacy names) |
| Runtime home | `~/.MobSF` | `~/.MobInspect` |
| Default database | SQLite `mobsf` | PostgreSQL `mobinspect` (SQLite fallback removed) |
| Docker user / image | `mobsf`, upstream image | `mobinspect`, `appdirsdev/mobinspect` |
| API header / key prefix | `X-Mobsf-Api-Key` | `X-MobInspect-Api-Key`, per-user keys `mi_<prefix>_<secret>` |
| UI, logo, strings | upstream branding | MobInspect brand, medallion-M mark |

## What that pass got wrong

The rename was a blind case-preserving find-and-replace applied to *every* occurrence of the
upstream name, including places where the name was an identifier of an upstream feature, a URL, or
prose about the upstream project. Workstream W1 of the agent contract reverses these:

- **Invented identifiers** — the upstream "prepare the device" feature became `mobinspecty` /
  `is_mobinspectyied`; the emulator became `MobInspect_API30`. Now `prepare_device` and
  `MobInspect_AVD`; the old API path `api/v1/android/mobinspecty` stays as a deprecated alias for one
  release.
- **Dead links** — 98 OWASP MSTG references in the rule files, the docs site, and contribution
  links pointed at a `github.com/MobInspect/...` organisation that does not exist. They now point at
  OWASP's repository or at this project.
- **Foreign community files** — `.github/SECURITY.md` carried the upstream project's security
  advisories relabelled as ours; the contributing/support/issue templates carried an upstream
  chat-workspace invite. Rewritten for this project.
- **Prose** — sentences such as "rename MobInspect to MobInspect" and "upstream MobInspect". Rewritten
  to say "the upstream project".

## What intentionally remains

| Where | What | Why |
|---|---|---|
| `LICENSE.md`, `NOTICE` | upstream copyright and contributor roster | GPL-3.0 §4–5 require keeping notices (decision D1) |
| `mobinspect/signatures/maltrail-malware-domains.txt` | a domain containing the author's org name | third-party threat-intel data |
| `mobinspect/DynamicAnalyzer/views/android/environment.py` | package id `opensecurity.clipdump` | compiled into the bundled `ClipDump.apk`; changes only with a rebuilt, re-signed APK |
| `mobinspect/StaticAnalyzer/tests.py` | a Java path inside a test APK fixture | fixture content |
| `project-memory/`, `claude-memory/` | session notes | tracked, excluded from images (decision D2) |
| `docs/agent-contract/`, `CHANGELOG.md`, `.claude/rules/` | describe the work | must name what was replaced |

## Not renamed

The Django project module `mobinspect/MobInspect/` keeps its mixed case. It owns no database tables,
but `mobinspect.MobInspect.settings/urls/wsgi` is referenced by `manage.py`, `mobinspect/__main__.py`,
`wsgi.py`, `pyproject.toml`, the e2e suite, both Dockerfiles, every entrypoint and the systemd units.
Renaming it is churn with deploy risk and no user-visible value.

## Verification

```
scripts/check-rebrand.sh          # exit 0 = complete
```
