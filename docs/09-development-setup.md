# 09 — Development Setup

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Python | 3.12+ | Inherited from upstream MobSF |
| Poetry | ≥1.5 | Package manager |
| Git | any | duh |
| `make` | any | Convenience commands |
| **Tailwind CLI** | bundled in `tools/` | CSS build |
| Java JDK | 17+ | Required by JADX, apktool for static analysis |
| (Optional) PostgreSQL | 14+ | If you want to test Postgres backend |
| (Optional) Android SDK + emulator | latest | For dynamic analysis development |
| (Optional) `wkhtmltopdf` | 0.12.6 | For PDF report generation |

## First-time setup

```bash
# 1. Clone
git clone https://github.com/<your-org>/MobInspect.git
cd MobInspect

# 2. Create the working branch (until rebrand lands)
git checkout -b mobinspect

# 3. Install Python deps
poetry install

# 4. Tailwind binary (one-time download)
./scripts/install-tailwind.sh        # downloads + verifies sha256

# 5. Build CSS once
./scripts/tailwind-build.sh

# 6. Initialize database & seed RBAC defaults
poetry run python manage.py migrate
poetry run python manage.py seed_rbac      # creates default roles + permissions

# 7. Create an admin user
poetry run python manage.py createsuperuser

# 8. Run the dev server
poetry run python manage.py runserver  # NOTE: blocked upstream, see below
# OR
poetry run mobsf                       # production-style server (gunicorn)
```

> Upstream MobSF blocks `manage.py runserver` (`manage.py:13`) for safety reasons. We unblock it under `MOBINSPECT_DEV=1`. Never set this in production.

## Daily development loop

Two terminals:

```bash
# Terminal 1: Tailwind in watch mode (~5ms rebuilds)
./scripts/tailwind-watch.sh

# Terminal 2: Django dev server with auto-reload
MOBINSPECT_DEV=1 MOBINSPECT_DEBUG=1 poetry run python manage.py runserver
```

## Useful environment variables (dev)

| Var | Value | Effect |
|-----|-------|--------|
| `MOBINSPECT_DEBUG=1` | — | Django DEBUG mode, full tracebacks |
| `MOBINSPECT_DISABLE_AUTHENTICATION=1` | — | Skip login (for quick UI iteration) |
| `MOBINSPECT_DEV=1` | — | Allow `runserver`, enable `/playground/` route |
| `POSTGRES_*` | — | Use Postgres instead of SQLite |
| `MOBINSPECT_ASYNC_ANALYSIS=0` | — | ON by default; set to `0` to force synchronous in-request scans instead of the `django-q2` worker |

## Useful commands

```bash
# Run linters
poetry run ruff check .
poetry run ruff format --check .

# Run tests
poetry run pytest -x                              # fast feedback
poetry run pytest tests/test_rbac.py -v           # one module

# Tailwind one-shot prod build
./scripts/tailwind-build.sh --minify

# Rebuild RBAC fixtures from current code
poetry run python manage.py seed_rbac --reset

# Backfill analytics from existing scans
poetry run python manage.py rebuild_analytics

# Show every URL the app exposes (debug routing)
poetry run python manage.py show_urls

# Inspect role / permissions of a user
poetry run python manage.py whoami <username>
```

## Project layout (target — post-Phase 3)

```
.
├── docs/                         ← you are here
├── mobinspect/
│   ├── MobInspect/               ← core app (settings, urls, wsgi, base views)
│   │   ├── settings.py
│   │   ├── urls.py
│   │   ├── views/
│   │   ├── middleware/
│   │   ├── templatetags/
│   │   └── templates/
│   ├── StaticAnalyzer/
│   ├── DynamicAnalyzer/
│   ├── MalwareAnalyzer/
│   ├── RBAC/                     ← Phase 1
│   ├── Analytics/                ← Phase 2.4
│   ├── static/
│   │   ├── mobinspect/
│   │   │   ├── css/app.css       ← Tailwind output
│   │   │   ├── fonts/
│   │   │   ├── img/              ← logos, illustrations
│   │   │   └── vendor/           ← Alpine, HTMX, Motion One, Chart.js, Lucide
│   │   └── (legacy adminlte/, etc — removed after Phase 2 complete)
│   └── templates/
│       ├── base/app.html         ← new base layout
│       ├── components/
│       └── (page templates)
├── scripts/
│   ├── tailwind-watch.sh
│   ├── tailwind-build.sh
│   ├── install-tailwind.sh
│   ├── rename-package.sh         ← Phase 3 helper
│   └── seed_rbac.py
├── tools/
│   └── tailwindcss-<version>     ← committed binary
├── tailwind.config.js
├── pyproject.toml
├── manage.py
└── README.md
```

## Testing matrix

| Layer | Tool | Lives in |
|-------|------|----------|
| Unit (Python) | pytest + pytest-django | `tests/` |
| Models & migrations | pytest fixtures + factory_boy | `tests/test_rbac.py`, etc. |
| View permissions | `pytest --cov=mobinspect.RBAC` with role-aware test client | `tests/test_views_rbac.py` |
| API contract | pytest with `requests` / Django test client | `tests/test_api.py` |
| Visual regression | playwright + pixelmatch (optional, Phase 4) | `tests/visual/` |
| Accessibility | pa11y in CI (optional, Phase 4) | `tests/a11y/` |

## CI

GitHub Actions workflow at `.github/workflows/ci.yml`:

1. Install Python + Poetry, install deps
2. Lint (ruff)
3. Build Tailwind, verify no `class="..."` references missing class definitions
4. Test (pytest)
5. (Phase 4) pa11y, playwright

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Theme flicker on first paint | `static/mobinspect/css/app.css` not loaded synchronously | Confirm `<link rel="stylesheet">` is before `<body>` |
| Class doesn't apply | Tailwind hasn't seen the template | Check `content` glob in `tailwind.config.js` includes that path |
| HTMX request returns 403 | CSRF | Add `hx-headers='{"X-CSRFToken": "{{ csrf_token }}"}'` or use the `htmx-csrf` snippet in `base/app.html` |
| `seed_rbac` re-creates roles every run | — | It's idempotent; check log for `created=False` |
| Migration says "no migrations to apply" but tables missing | Wrong `INSTALLED_APPS` order | Add `mobinspect.RBAC` after `django.contrib.auth` |
