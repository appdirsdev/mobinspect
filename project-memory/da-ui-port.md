---
name: da-ui-port
description: "Which Dynamic Analysis templates were ported to the new MobInspect design system, and the legacy_app.html pattern"
metadata: 
  node_type: memory
  type: project
  originSessionId: cc2a3ba9-0869-4596-b93d-e1550cf847c2
---

MobInspect's redesign uses `base/app.html` (Tailwind design system: `app.css`, htmx, Alpine, `{% icon %}` from `mi_icons`, `.card`/`.btn`/`.input` component classes, `text-h*`/`text-text-*`/`bg-surface-*`/`border-border-subtle` tokens). `base/legacy_app.html` ITSELF `{% extends "base/app.html" %}` — it just adds jQuery + Bootstrap + AdminLTE + FontAwesome for pages whose inner markup still needs them. So a `legacy_app` page already gets the new chrome (sidebar/topbar/theme); only its `{% block content %}` may still be old AdminLTE.

**Ported to the new design this session (Android DA):**
- `dynamic_analysis/android/dynamic_analyzer.html` — the live analyzer at `/android_dynamic/<md5>`. Rewritten to extend `base/app.html` directly. Keeps jQuery + CodeMirror + EnlighterJS + Swipe + FontAwesome (loaded in `extra_head`/`extra_js`); Bootstrap modals → native `<dialog>` (`showModal()`/`close()`); tabs → Alpine `x-data`. Added `[x-cloak]{display:none}` (app.css ships none). Every original element id/JS handler preserved. Note: `--font-mono` CSS var does NOT exist in app.css — use a literal `'JetBrains Mono', ui-monospace, …` stack.
- `dynamic_analysis/android/dynamic_report.html` — the post-run report at `/dynamic_report/<md5>`. **Kept `base/legacy_app.html`** (needs jQuery+DataTables for `$('table').DataTable()` and amcharts for the `#chartdiv` world map) but restyled content to `.card`/`.card-header` + a custom `.mi-table` design-token table. All 16 sections + `|key:` bindings + amcharts/DataTables scripts preserved.

**Already visually consistent (leave on legacy_app for jQuery/DataTables JS):** android `live_api.html`, `frida_logs.html`; ios `api_monitor.html`, `system_logs.html`, `device/system_logs.html`.

**Still legacy, NOT yet ported (lower priority, iOS/Corellium-only or tiny):** ios `dynamic_report.html` (+`device/`), ios `dynamic_analyzer.html` (+`device/`), ios `dynamic_analysis.html` (+`device/`); app-wide `general/error.html` (20 lines) and `general/zip.html` (28 lines).

**Gotcha — the `key` filter:** `data|key:"name"` is used across report/analysis templates WITHOUT a `{% load %}`. It's registered globally via `register.filter('key', key)` in `StaticAnalyzer/views/android/static_analyzer.py` (util `mobinspect/MobInspect/utils.py:key`), so it works everywhere with only `{% load static %}`.

Related: [[dynamic-analysis-fixes]], [[compare-and-fonts]], [[start-script]].
