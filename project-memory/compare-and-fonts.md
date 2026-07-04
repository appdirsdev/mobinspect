---
name: compare-and-fonts
description: MobInspect scan-compare feature has no UI button; missing web fonts were added
metadata: 
  node_type: memory
  type: project
  originSessionId: ddb6a3a9-3aa7-4d11-bc01-6d22ba1f4ff1
---

Two smaller findings from working on MobInspect:

- **Scan comparison — UI added (was backend-only).** Backend: web route `/compare/<hash1>/<hash2>/` (now `name='compare_apps'`, `compare_apps` → `generic_compare`, renders `static_analysis/compare.html`) + REST `POST /api/v1/compare`. **Android only** (`comparer.py` reads only `StaticAnalyzerAndroid`); hashes must differ. A **"Compare versions" UI** was added: a `Compare` button on the Android binary (`android_binary_analysis.html`) and source (`android_source_analysis.html`) report headers → new route `/compare_versions/<md5>` (`name='compare_versions'`, view `shared_func.compare_versions`, template `static_analysis/compare_versions.html`). The picker lists other scanned versions of the same `PACKAGE_NAME` (from `StaticAnalyzerAndroid`, ordered via `RecentScansDB.TIMESTAMP`), each linking to the diff. Empty-state when no other versions are scanned. The `_app_header.html` shared partial (used by iOS/Windows/source reports, NOT android_binary_analysis which has its own inline header) also got the button gated to `platform_label == 'Android'`.

- **Missing web fonts (cosmetic 404s).** `mobsf/static/mobinspect/fonts/` was empty but `css/dist/app.css` `@font-face` references `Inter-Variable.woff2` and `JetBrainsMono-Variable.woff2`. Downloaded them from fontsource jsDelivr CDN into that dir. `STATIC_ROOT` == `mobsf/static` (BASE_DIR is the mobsf package), and whitenoise indexes static files once at startup (autorefresh pinned off), so a server restart is needed to serve newly added static files.

- **`VariableDoesNotExist: key [title]` in home.html** was harmless Django DEBUG-level template noise (`base/app.html` treats `title` as optional via `{% if title %}` / `{{ title|default:"" }}`; views like Home don't set it). **Now silenced** by raising the `django.template` logger to INFO in `settings.py` LOGGING (mirrors the existing `django.db.backends` INFO treatment). Needs a gunicorn restart.

Related: [[start-script]], [[toolchain]], [[da-ui-port]].
