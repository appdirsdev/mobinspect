# 01 — Architecture

## High-level shape

MobInspect is a **monolithic Django application** with five sub-apps and a small set of cross-cutting concerns. There are no microservices.

```
┌──────────────────────────────────────────────────────────────────┐
│                       Browser / API client                       │
│                  (Tailwind UI · HTMX · Alpine)                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │ HTTPS
┌──────────────────────────▼───────────────────────────────────────┐
│   Gunicorn / Waitress  →  Django (ROOT_URLCONF = MobSF.urls)     │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │  Middleware: CSRF · Session · Auth · Ratelimit · RBAC    │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   ┌─────────────┐ ┌─────────────────┐ ┌────────────────────┐     │
│   │   MobSF     │ │  StaticAnalyzer │ │  DynamicAnalyzer   │     │
│   │ (web + API) │ │  (apk/ipa/appx) │ │  (Frida + device)  │     │
│   └─────────────┘ └─────────────────┘ └────────────────────┘     │
│                ┌─────────────────────────────┐                   │
│                │       MalwareAnalyzer       │                   │
│                │ (VT · trackers · domains)   │                   │
│                └─────────────────────────────┘                   │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │           django-q2 worker pool (async scans)            │   │
│   └──────────────────────────────────────────────────────────┘   │
└──────────────────────────┬───────────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
        ┌─────▼─────┐            ┌──────▼──────┐
        │  SQLite/  │            │  $MOBSF_HOME│
        │  Postgres │            │   (uploads, │
        │           │            │  downloads, │
        │           │            │ signatures) │
        └───────────┘            └─────────────┘
```

## Django apps (current)

Defined in `mobsf/MobSF/settings.py:182`:

| App | Path | Responsibility |
|-----|------|----------------|
| `django_q` | external | Async task queue for long scans |
| `mobsf.MobSF` | `mobsf/MobSF/` | Web UI, REST API, auth, SAML, URL routing |
| `mobsf.StaticAnalyzer` | `mobsf/StaticAnalyzer/` | APK/IPA/APPX decompilation and code analysis |
| `mobsf.DynamicAnalyzer` | `mobsf/DynamicAnalyzer/` | Emulator/device control + Frida instrumentation |
| `mobsf.MalwareAnalyzer` | `mobsf/MalwareAnalyzer/` | VirusTotal, tracker detection, domain reputation |

## Django apps (target — adds for MobInspect)

| App | Path | Responsibility |
|-----|------|----------------|
| `mobinspect.RBAC` *[NEW]* | `mobinspect/RBAC/` | Role / Permission / Assignment models, admin UI |
| `mobinspect.Analytics` *[NEW]* | `mobinspect/Analytics/` | Aggregation queries + dashboard widgets |

These are added before the rebrand; once Phase 3 lands, all `mobsf.*` paths become `mobinspect.*`.

## Request lifecycle

1. **Edge** — Gunicorn (Linux/macOS) or Waitress (Windows) accepts the request. WhiteNoise serves `/static/`.
2. **Middleware chain** (`mobsf/MobSF/settings.py:195`):
   - `SecurityMiddleware` — security headers
   - `WhiteNoiseMiddleware` — static asset serving
   - `CommonMiddleware` — host validation
   - `CsrfViewMiddleware` — CSRF
   - `AuthenticationMiddleware` — populate `request.user`
   - `MessageMiddleware` — flash messages
   - `XFrameOptionsMiddleware` — clickjacking
   - `RatelimitMiddleware` — rate limiting (`django-ratelimit`)
   - **`RBACMiddleware` *[NEW]*** — populate `request.role`, `request.permissions`
3. **API path only** (`mobsf/MobSF/settings.py:206`):
   - `RestApiAuthMiddleware` — API-key auth, sets `request.api = True` for downstream views
4. **URL routing** — `mobsf/MobSF/urls.py` dispatches to one of:
   - Auth views (`authentication.py`, `authorization.py`, `saml2.py`)
   - Web home / scan submission (`home.py`, `scanning.py`)
   - Static analyzer views (Android / iOS / Windows)
   - Dynamic analyzer views (Android / iOS Corellium / iOS device)
   - REST API views (`api/api_static_analysis.py`, `api/api_android_dynamic_analysis.py`, ...)
5. **View** — runs synchronously or enqueues a `django-q2` task for async scans (`MOBSF_ASYNC_ANALYSIS=1`).
6. **Template** — server-rendered Django template under `mobsf/templates/`. After Phase 2, all templates use the new `base/app.html` layout.
7. **Response** — full HTML page or HTMX fragment for partial updates.

## Data flow — a static scan

```
upload(.apk)
   │
   ▼
[scanning.upload]  ──► save to MOBSF_HOME/uploads/<md5>/
   │
   ▼
[StaticAnalyzer.android.static_analyzer.static_analyzer]
   │
   ├─► Androguard — manifest, permissions, certs
   ├─► JADX       — decompile to Java
   ├─► libsast    — pattern-based code analysis
   ├─► APKiD      — packer / obfuscator detection
   ├─► LIEF       — native binary analysis
   └─► MalwareAnalyzer — VT, trackers, domains
   │
   ▼
StaticAnalyzerAndroid model (mobsf/StaticAnalyzer/models.py)
   │
   ▼
Render report template / return JSON via API
```

## Filesystem layout — target state

```
Mobile-Security-Framework-MobSF/      # repo root (not renamed; only Python pkg renames)
├── docs/                             # this directory
├── mobinspect/                       # Python package (was mobsf/)
│   ├── MobInspect/                   # core app (was MobSF/)
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── views/
│   │   └── templates/
│   ├── StaticAnalyzer/
│   ├── DynamicAnalyzer/
│   ├── MalwareAnalyzer/
│   ├── RBAC/                         # NEW
│   ├── Analytics/                    # NEW
│   ├── static/
│   │   ├── mobinspect/               # NEW — Tailwind CSS, JS bundles
│   │   ├── adminlte/                 # KEPT until Phase 2 fully migrates
│   │   └── ...
│   └── templates/
│       ├── base/
│       │   ├── app.html              # NEW base layout
│       │   └── ...
│       └── ...
├── tailwind.config.js                # NEW
├── package.json                      # NEW (devDependency: tailwindcss CLI)
└── ...
```

## Persistence

| Store | Engine | Purpose |
|-------|--------|---------|
| Relational DB | SQLite (default) or Postgres (`POSTGRES_*` envs) | Scan metadata, users, roles, permissions, suppressions, async tasks |
| Filesystem | `$MOBSF_HOME/uploads/<md5>/` | Uploaded binaries and decompiled output |
| Filesystem | `$MOBSF_HOME/downloads/` | Generated artifacts (PDFs, screenshots) |
| Filesystem | `$MOBSF_HOME/signatures/` | Malware signatures, DBs |

`$MOBSF_HOME` defaults to `~/.MobSF/` and becomes `~/.MobInspect/` after Phase 3.

## What we are intentionally not changing

- **Analysis engine** — `StaticAnalyzer`, `DynamicAnalyzer`, `MalwareAnalyzer` internals stay byte-for-byte where possible
- **Database schema for scan results** — additive only; we do not migrate existing scan tables
- **API contract** — REST endpoints keep their paths, request/response shapes, and auth model
- **CLI behaviour of the `mobsf` command** — until Phase 3 renames it to `mobinspect`
