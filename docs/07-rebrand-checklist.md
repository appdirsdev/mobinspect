# 07 — Rebrand Checklist (MobSF → MobInspect)

> Phase 3 of the roadmap. Run only after the new UI and RBAC have stabilized.
> The repository directory name (`Mobile-Security-Framework-MobSF`) is **not** renamed — only the Python package, env vars, paths, and user-visible strings.

## Strategy

A naive global find/replace will break licensing strings, third-party API URLs, and binary file references. The checklist below splits the work into **four passes**, each scoped, reviewable in a single commit.

## Pass 1 — Python package rename

```
mobsf/                  →  mobinspect/
mobsf/MobSF/            →  mobinspect/MobInspect/
mobsf.MobSF             →  mobinspect.MobInspect
mobsf.StaticAnalyzer    →  mobinspect.StaticAnalyzer
mobsf.DynamicAnalyzer   →  mobinspect.DynamicAnalyzer
mobsf.MalwareAnalyzer   →  mobinspect.MalwareAnalyzer
```

### Files affected
- `pyproject.toml:2` — `name = "mobsf"` → `"mobinspect"`
- `pyproject.toml:11` — `packages = [{include = "mobsf", ...}]` → `"mobinspect"`
- `pyproject.toml:23` — `mobsf = "mobsf.__main__:main"` → `mobinspect = "mobinspect.__main__:main"`
- `mobsf/__main__.py:9` — `DJANGO_SETTINGS_MODULE` → `mobinspect.MobInspect.settings`
- `mobsf/__main__.py:52,66` — wsgi import path
- `manage.py` — settings module reference
- `tox.ini` — module references
- All `from mobsf.*` and `import mobsf.*` lines (~600 occurrences across `mobsf/`)
- All Django app `apps.py` `name = 'mobsf...'` declarations
- Migration `dependencies` references — all migrations under `mobsf/*/migrations/`

### Procedure
1. `git mv mobsf mobinspect`
2. Within `mobinspect/`, `git mv MobSF MobInspect`
3. Run an automated rewrite script (committed to `scripts/rename-package.sh`) that does the AST-aware import rewrite — fall back to `sed` only for non-Python text
4. Run all tests; fix any breakages
5. Rebuild migrations: `python manage.py makemigrations --check` should report nothing
6. Single commit: `chore(rebrand): rename python package mobsf → mobinspect`

## Pass 2 — Environment variables and runtime paths

| Old | New |
|-----|-----|
| `MOBSF_HOME` | `MOBINSPECT_HOME` |
| `MOBSF_API_KEY` | `MOBINSPECT_API_KEY` |
| `MOBSF_API_KEY_FILE` | `MOBINSPECT_API_KEY_FILE` |
| `MOBSF_API_ONLY` | `MOBINSPECT_API_ONLY` |
| `MOBSF_DEBUG` | `MOBINSPECT_DEBUG` |
| `MOBSF_DISABLE_AUTHENTICATION` | `MOBINSPECT_DISABLE_AUTHENTICATION` |
| `MOBSF_PLATFORM` | `MOBINSPECT_PLATFORM` |
| `MOBSF_USER` | `MOBINSPECT_USER` |
| `MOBSF_ASYNC_*` | `MOBINSPECT_ASYNC_*` |
| `MOBSF_RATELIMIT` | `MOBINSPECT_RATELIMIT` |
| `MOBSF_IDP_*` | `MOBINSPECT_IDP_*` |
| `MOBSF_SP_*` | `MOBINSPECT_SP_*` |
| `MOBSF_VT_*` | `MOBINSPECT_VT_*` |
| `MOBSF_CORELLIUM_*` | `MOBINSPECT_CORELLIUM_*` |
| `MOBSF_PROXY_*` / `MOBSF_UPSTREAM_PROXY_*` | `MOBINSPECT_*` |
| `MOBSF_FRIDA_TIMEOUT` | `MOBINSPECT_FRIDA_TIMEOUT` |
| `MOBSF_JADX_TIMEOUT` | `MOBINSPECT_JADX_TIMEOUT` |
| `MOBSF_SAST_TIMEOUT` | `MOBINSPECT_SAST_TIMEOUT` |
| `MOBSF_BINARY_ANALYSIS_TIMEOUT` | `MOBINSPECT_BINARY_ANALYSIS_TIMEOUT` |
| `MOBSF_*_BINARY` (paths to JADX, apktool, etc.) | `MOBINSPECT_*_BINARY` |
| Default home dir `~/.MobSF/` | `~/.MobInspect/` |
| Database default name `mobsf` (Postgres) | `mobinspect` |
| `MOBSF_DOMAIN_MALWARE_SCAN`, `MOBSF_APKID_ENABLED`, etc. | `MOBINSPECT_*` |

### Backwards compatibility shim
Read both old and new env vars during a 1-release deprecation window:

```python
def env(new, old=None, default=''):
    val = os.getenv(new)
    if val is not None:
        return val
    if old is not None and os.getenv(old) is not None:
        warnings.warn(
            f'{old} is deprecated; use {new}', DeprecationWarning,
        )
        return os.getenv(old)
    return default
```

After v1.0 of MobInspect ships, the shim is removed in v1.1.

### Filesystem paths
- `~/.MobSF/` → migrate to `~/.MobInspect/` on first run if old dir exists
- `~/.MobSF/config.py` → loaded but written back to `~/.MobInspect/config.py` with a one-line warning

## Pass 3 — User-visible strings, branding assets

### Strings
- All occurrences of "MobSF" in templates → "MobInspect"
- All occurrences in flash messages, error pages, page titles, breadcrumbs
- "Mobile Security Framework" subtitle → "Mobile Application Security Inspector" (subtitle TBD)
- README.md — top sentence, badges, screenshots
- LICENSE file unchanged (GPL-3.0 verbatim)
- LICENSES/ — unchanged (third-party notices stay)
- Source file headers — **append** new copyright, do not replace original

### Assets to replace
| Path | Asset |
|------|-------|
| `mobsf/static/img/favicon.ico` | new favicon |
| `mobsf/static/img/mobsf_logo.png` | new wordmark — light variant |
| `mobsf/static/img/mobsf_logo_dark.png` | new wordmark — dark variant |
| `mobsf/static/img/mobsf-logo-square.png` | square logo (avatars, OG image) |
| `mobsf/templates/pdf/header.html` | PDF report header logo |
| Open Graph image referenced in `base/app.html` | og-image-1200x630.png |

Logo brief is owned by design; see `docs/design/logo-brief.md` (to be created).

### Page titles / metadata
- HTML `<title>` template: `{% block page_title %}{% endblock %} · MobInspect` (was `... · MobSF`)
- `<meta name="description">` updated to MobInspect tagline
- Manifest / web app metadata if PWA-ish features added later

## Pass 4 — Build & deployment

### Dockerfile
- `LABEL name="MobSF"` → `name="MobInspect"`
- `MOBSF_USER` → `MOBINSPECT_USER`
- `DJANGO_SUPERUSER_USERNAME=mobsf` → `mobinspect`
- `WORKDIR /home/mobsf/Mobile-Security-Framework-MobSF` → `/home/mobinspect/MobInspect`
- All `mobsf` user/group references
- Image tag/name (project decision: keep repo name, change image name to `mobinspect/mobinspect`)

### run.sh / run.bat
- `gunicorn ... mobsf.MobSF.wsgi:application` → `mobinspect.MobInspect.wsgi:application`

### scripts/
- `dependencies.sh`, `entrypoint.sh` — any path/var references
- `setup.sh`, `setup.bat`

### CI
- `.github/workflows/*.yml` — image names, env var names
- Sonar config (`.sonarcloud.properties`) — project key

### Documentation
- README.md — full rewrite of the intro paragraph; keep MobSF attribution paragraph at the bottom
- All `docs/*.md` references that are still legacy
- API docs — generated from URL conf; should auto-update when string constants change

### External references (do not change)
- The `MOBSF`/`mobsf` strings inside **third-party API user agents or webhook payloads** stay if they're documented as part of the integration contract
- `apkid.MobSF` references in tooling that isn't ours
- Public URLs of the upstream MobSF project (in attribution links)

## Verification

After each pass, run:

```bash
# Pass 1
poetry install --no-root && poetry run pytest

# Pass 2
MOBINSPECT_HOME=/tmp/mi-test poetry run mobinspect    # boots cleanly

# Pass 3
# Manual: open every page in light + dark, confirm brand strings

# Pass 4
docker build -t mobinspect:test . && docker run --rm -p 8000:8000 mobinspect:test
```

Deferred-fail checks (not blocking):
- `grep -rn 'MobSF' mobinspect/` returns only intentional attribution lines
- `grep -rn 'MOBSF_' mobinspect/` returns only the deprecation shim
- `find mobinspect -name '*MobSF*'` returns empty
