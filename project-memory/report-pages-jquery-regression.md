---
name: report-pages-jquery-regression
description: "FIXED 2026-07-14 — report pages were missing jQuery / crashing DataTables on empty-state tables; now resolved, see fix details below"
metadata: 
  node_type: memory
  type: project
  originSessionId: 67019f0b-e557-4966-8b9c-683562465919
---

**FIXED 2026-07-14**, commit "Gate AI Dashboard button to completed scans; fix report-page jQuery errors" on `feature/granite-llm-integration` (pushed to GitHub). Two root causes, two fixes:
1. `android_binary_analysis.html`/`ios_binary_analysis.html` never included `jquery.min.js` at all (only the source-analysis templates did) — added the missing `<script src="{% static 'adminlte/plugins/jquery.min.js' %}">` include to both.
2. `datatables_init.js`'s blanket `$('table').DataTable(...)` crashed with "Incorrect column count" on any report table whose only body row is the standard colspan empty-state placeholder (the Responsive extension misreads the colspan). Fixed by skipping DataTable init on tables matching that exact single-row-all-colspan shape.
Also fixed a duplicate `id="table_file"`/`id="table_code"` collision in `android_source_analysis.html` (NIAP analysis + File analysis shared one id; Behaviour analysis + Code analysis shared another) — renamed to `table_niap`/`table_behaviour` so the Behaviour-analysis suppress feature isn't silently broken by DataTables/jQuery only ever binding to the first matching id.
Verified via live Playwright console-error checks on all 4 report-page types (android/ios × binary/source): 0 console errors, `typeof jQuery === 'function'` on every page.

Original finding, for history — found during the all-formats E2E sweep (2026-07-13). NOT from the AI work.

The scan **report pages** (`static_analysis/{android,ios}_{binary,source}_analysis.html`, `source_tree.html`) extend the redesigned shell `base/app.html`, which loads **no jQuery** (`grep -c jquery` = 0). But those templates still `{% static %}`-include legacy **AdminLTE jQuery plugins** (e.g. sweetalert2) and use `$(this.closest('tr'))` in the finding-**suppress** `onclick` handlers. Result: every Android/iOS report page emits 3 load-time JS errors — `jQuery is not defined` / `$ is not defined` — and the **finding-suppression feature is broken** (jQuery `$` undefined at click). The report itself renders fully (HTTP 200, all data/sections, no overflow); only the jQuery-dependent interactions fail. Windows (appx) report page is clean (0 errors — different template).

jQuery IS still loaded in the LEGACY bases (`base/base_layout.html`, `base/legacy_app.html`) — the redesigned report templates were migrated off those without porting the suppress JS or the plugin deps.

**Fix options (a decision, not yet done):** (a) vanilla-ize `suppress()` + drop the legacy AdminLTE plugin includes (matches the redesign's alpine/vanilla direction), or (b) re-add a local jQuery to the report templates. The **AI Dashboard is unaffected** — it uses locally-vendored htmx + Alpine (`base/app.html:356-357`) and rendered with 0 JS errors. See [[fullsweep-redesign-tests]], [[design-system-conventions]].
