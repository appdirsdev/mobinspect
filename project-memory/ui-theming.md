---
name: ui-theming
description: "How dark-mode \"white boxes\" were fixed across MobInspect — the two override layers + where hardcoded colors live"
metadata: 
  node_type: memory
  type: project
  originSessionId: cc2a3ba9-0869-4596-b93d-e1550cf847c2
---

Dark mode = `<html data-theme="dark">` (set by `mobinspect/js/theme.js` from `localStorage('mi-theme')` = light|dark|system). `app.css` themes via `[data-theme]` tokens: `--surface-0..4`, `--border-subtle/-default/-strong`, `--text-primary/-secondary/-tertiary/-brand/-inverse` — used as `rgb(var(--NAME))`.

**Why pages showed white in dark mode + the two fixes:**

1. **Bootstrap/AdminLTE components** (`.card`/`.table`/`.modal`/`.form-control`…) on `legacy_app.html` pages: AdminLTE CSS loads AFTER `app.css` and hardcodes `background:#fff`, overriding the design system. **Fixed once** with a big `<style>` block in `base/legacy_app.html` that re-maps all those components to `rgb(var(--surface-*))` etc. — covers all ~15 legacy pages.

2. **Third-party widgets** (CodeMirror, highlight.js `.hljs`, jsTree, EnlighterJS, DataTables) whose vendor CSS is hardcoded light. These pages extend `base/app.html` DIRECTLY (so the legacy override doesn't reach them). **Fixed once** with a `<style id="mi-widget-dark-theme">` block in `base/app.html`, scoped `[data-theme="dark"]` so light mode keeps the vendor look.

3. **Page-specific inline hardcodes** fixed individually: `android_binary_analysis.html` `.mi-list` used `var(--text-brand)` WITHOUT `rgb()` (tokens are channel triplets → invalid → dropped); `source_tree.html`/`view.html` enlighter line-highlight `#fff8bb`; iOS analyzer `#code-editor`/`#stat`/`#er` hardcoded light; report `#chartdiv` amcharts.

**Gotchas:** tokens are `R G B` triplets, so always `rgb(var(--x))` / `rgb(var(--x) / 0.5)`, never bare `var(--x)`. `DEBUG=False` (default) means Django uses the **cached template loader** → every template edit needs a `kill -HUP <gunicorn master>` to show up. `pdf/*` templates are intentionally light (print) — see [[pdf-report]].

Related: [[da-ui-port]], [[pdf-report]].
