---
name: toolchain
description: "How MobInspect's local dev environment is installed (Python, Poetry, PostgreSQL, Android SDK)"
metadata: 
  node_type: memory
  type: project
  originSessionId: ddb6a3a9-3aa7-4d11-bc01-6d22ba1f4ff1
---

MobInspect (a MobInspect fork, Django app) local dev toolchain on this macOS (Apple Silicon) machine:

- **Python 3.13.5** via pyenv (`~/.pyenv/versions/3.13.5/bin/python`). Project pins it in `.python-version`; system python is 3.9, brew has 3.14 (both incompatible — setup.sh requires 3.12–3.13).
- **Poetry 1.8.4** installed into that 3.13.5 interpreter. Virtualenv: `~/Library/Caches/pypoetry/virtualenvs/mobinspect-sdY5Kvc2-py3.13`. Deps installed via `poetry install --no-root --only main`.
- **PostgreSQL 16** (`brew services`), role `mobinspect` / db `mobinspect` / password `mobinspect`. App uses SQLite by default and only switches to Postgres when `POSTGRES_USER/PASSWORD/HOST` env vars are set (see `.env.postgres`).
- **Android SDK**: OpenJDK 17 (`/opt/homebrew/opt/openjdk@17`), cmdline-tools + platform-tools (brew), emulator + `system-images;android-34;google_apis;arm64-v8a`, `ANDROID_HOME=~/Library/Android/sdk`. AVD name `MobInspect_API34`.
- Admin login bootstrapped: `admin` / `Admin@12345` (via `MOBINSPECT_ADMIN_PASSWORD`; change after first login).
- **wkhtmltopdf 0.12.6** (for PDF report export) at `~/.local/wkhtmltox/bin/wkhtmltopdf`. Homebrew dropped the formula/cask (upstream archived 2023), so it was installed from the official `wkhtmltopdf/packaging` 0.12.6-2 macOS pkg — extracted **without sudo** via `pkgutil --expand-full` then untarring the nested `Payload/usr/local/share/wkhtmltox-installer/wkhtmltox.tar.gz`. It's an x86_64 build (runs under Rosetta). MobInspect reads env `MOBINSPECT_WKHTMLTOPDF_BINARY` → `settings.WKHTMLTOPDF_BINARY` (pdf.py); `start.sh` exports it. Without it, `/pdf/<md5>/` returns HTTP 503. Verified: renders the full ~67-page report.

See [[start-script]] for the single-command launcher and [[dynamic-analysis-fixes]] for DA gotchas.
