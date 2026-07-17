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
│   Gunicorn / Waitress  →  Django (ROOT_URLCONF = MobInspect.urls)     │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │  Middleware: CSRF · Session · Auth · Ratelimit · RBAC    │   │
│   └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│   ┌─────────────┐ ┌─────────────────┐ ┌────────────────────┐     │
│   │   MobInspect     │ │  StaticAnalyzer │ │  DynamicAnalyzer   │     │
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
        │  SQLite/  │            │  $MOBINSPECT_HOME│
        │  Postgres │            │   (uploads, │
        │           │            │  downloads, │
        │           │            │ signatures) │
        └───────────┘            └─────────────┘
```

## Django apps (current)

Defined in `mobinspect/MobInspect/settings.py:182`:

| App | Path | Responsibility |
|-----|------|----------------|
| `django_q` | external | Async task queue for long scans |
| `mobinspect.MobInspect` | `mobinspect/MobInspect/` | Web UI, REST API, auth, SAML, URL routing |
| `mobinspect.StaticAnalyzer` | `mobinspect/StaticAnalyzer/` | APK/IPA/APPX decompilation and code analysis |
| `mobinspect.DynamicAnalyzer` | `mobinspect/DynamicAnalyzer/` | Emulator/device control + Frida instrumentation |
| `mobinspect.MalwareAnalyzer` | `mobinspect/MalwareAnalyzer/` | VirusTotal, tracker detection, domain reputation |

## Django apps (target — adds for MobInspect)

| App | Path | Responsibility |
|-----|------|----------------|
| `mobinspect.RBAC` *[NEW]* | `mobinspect/RBAC/` | Role / Permission / Assignment models, admin UI |
| `mobinspect.Analytics` *[NEW]* | `mobinspect/Analytics/` | Aggregation queries + dashboard widgets |

These are added before the rebrand; once Phase 3 lands, all `mobinspect.*` paths become `mobinspect.*`.

## Request lifecycle

1. **Edge** — Gunicorn (Linux/macOS) or Waitress (Windows) accepts the request. WhiteNoise serves `/static/`.
2. **Middleware chain** (`mobinspect/MobInspect/settings.py:195`):
   - `SecurityMiddleware` — security headers
   - `WhiteNoiseMiddleware` — static asset serving
   - `CommonMiddleware` — host validation
   - `CsrfViewMiddleware` — CSRF
   - `AuthenticationMiddleware` — populate `request.user`
   - `MessageMiddleware` — flash messages
   - `XFrameOptionsMiddleware` — clickjacking
   - `RatelimitMiddleware` — rate limiting (`django-ratelimit`)
   - **`RBACMiddleware` *[NEW]*** — populate `request.role`, `request.permissions`
3. **API path only** (`mobinspect/MobInspect/settings.py:206`):
   - `RestApiAuthMiddleware` — API-key auth, sets `request.api = True` for downstream views
4. **URL routing** — `mobinspect/MobInspect/urls.py` dispatches to one of:
   - Auth views (`authentication.py`, `authorization.py`, `saml2.py`)
   - Web home / scan submission (`home.py`, `scanning.py`)
   - Static analyzer views (Android / iOS / Windows)
   - Dynamic analyzer views (Android / iOS Corellium / iOS device)
   - REST API views (`api/api_static_analysis.py`, `api/api_android_dynamic_analysis.py`, ...)
5. **View** — enqueues a `django-q2` task for async scans by default (`MOBINSPECT_ASYNC_ANALYSIS`, default `1`) or runs synchronously if disabled.
6. **Template** — server-rendered Django template under `mobinspect/templates/`. After Phase 2, all templates use the new `base/app.html` layout.
7. **Response** — full HTML page or HTMX fragment for partial updates.

## Data flow — a static scan

```
upload(.apk)
   │
   ▼
[scanning.upload]  ──► save to MOBINSPECT_HOME/uploads/<md5>/
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
StaticAnalyzerAndroid model (mobinspect/StaticAnalyzer/models.py)
   │
   ▼
Render report template / return JSON via API
```

## Filesystem layout — target state

```
mobinspect/      # repo root (not renamed; only Python pkg renames)
├── docs/                             # this directory
├── mobinspect/                       # Python package (was mobinspect/)
│   ├── MobInspect/                   # core app (was MobInspect/)
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
| Filesystem | `$MOBINSPECT_HOME/uploads/<md5>/` | Uploaded binaries and decompiled output |
| Filesystem | `$MOBINSPECT_HOME/downloads/` | Generated artifacts (PDFs, screenshots) |
| Filesystem | `$MOBINSPECT_HOME/signatures/` | Malware signatures, DBs |

`$MOBINSPECT_HOME` defaults to `~/.MobInspect/` and becomes `~/.MobInspect/` after Phase 3.

## What we are intentionally not changing

- **Analysis engine** — `StaticAnalyzer`, `DynamicAnalyzer`, `MalwareAnalyzer` internals stay byte-for-byte where possible
- **Database schema for scan results** — additive only; we do not migrate existing scan tables
- **API contract** — REST endpoints keep their paths, request/response shapes, and auth model
- **CLI behaviour of the `mobinspect` command** — until Phase 3 renames it to `mobinspect`
