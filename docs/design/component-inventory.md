# Component Inventory

Component inventory for the MobInspect redesign. The original premise here was
that every item on this list becomes its own Django include under
`mobinspect/templates/components/<name>.html`. That's not what actually happened:
a handful of genuinely reusable, non-trivial widgets did become real includes
(`gauge_arc`, `dot_matrix`, `sidebar`, `sidebar_item`, `topbar`, `logo_mark` —
all live under `mobinspect/templates/components/`), but most of what people mean
by "button", "input", "card", "badge" shipped instead as a small set of CSS
utility classes in `mobinspect/static/mobinspect/css/src/app.css`'s
`@layer components`, applied directly in markup (`class="btn btn-primary
btn-md"`) rather than `{% include %}`d. That's a legitimate, lighter-weight
way to get a consistent system in a server-rendered, non-SPA Django app — it
just means the statuses below describe what's real in the repo today, not
whether it matches the doc's original literal-include framing.

Status: `□` not started · `▣` in progress / partial · `■` done

Every `■` below points at a real file/class you can open right now. Nothing
is marked done on the strength of "it's probably fine" or "it was old so it
must be superseded."

## Inputs

- ■ `button` — variants + sizes shipped as CSS, not a template include: `.btn` base + `.btn-sm/md/lg` + `.btn-primary/secondary/ghost/danger/link` in `app.css` `@layer components`. No dedicated loading-state or icon-leading/trailing CSS variant — those remain plain markup conventions if a page needs them.
- □ `icon_button` — no shared square/icon-only variant or badge-dot convention. Icon-only buttons exist ad hoc per page (topbar theme toggle, sidebar collapse control) with their own one-off sizing.
- ■ `input` — `.input` + `.label` in `app.css`; used across forms and the per-page search bars below. No leading/trailing-icon slot convention.
- □ `textarea` — not built.
- ▣ `select` — native `<select>` reuses `.input` directly (e.g. `auth/register.html`'s role picker: `class="input pl-9"`). No searchable/Alpine variant.
- □ `checkbox` — plain unstyled native checkboxes still used where needed (e.g. `rbac/role_form.html` permission list); no labeled/hinted checkbox component.
- □ `radio` — not built.
- □ `toggle` — no animated-thumb switch exists anywhere in the templates.
- □ `file_upload` — `general/home.html` / `general/zip.html` still use the original pre-redesign upload form; no drag-drop dropzone, multi-file, or progress UI.
- ▣ `search` — real per-page search bars shipped (`.mi-search` + clear button + client-side filtering, in `auth/users.html`, `general/recent.html`, `rbac/permissions.html`), but there's no global `⌘K` command-style search bar.
- ■ `color_picker` — `rbac/role_form.html`'s `.rf-swatch` preset-palette swatches (8 fixed hexes incl. brand blue) — matches the "preset palette only" spec.
- ■ `icon_picker` — `rbac/role_form.html`'s `.rf-icon-btn` Lucide icon grid, alongside the color picker.

## Containers

- ■ `card` — `.card` / `.card-hover` / `.card-header` / `.card-body` / `.card-footer` in `app.css`.
  - ■ **`.mi-glass`** (not on the original list) — a glass-surface utility layered on top of `.card` (`mobinspect/templates/base/app.html`, `#mi-chrome` style block): `backdrop-filter: blur()+saturate()` for a translucent card. Deliberately opt-in per element (`class="card mi-glass"`), *not* forced onto the base `.card` class app-wide — dense tables/forms intentionally stay opaque for legibility.
- □ `panel` — not built.
- □ `modal` — not built as part of this redesign. The `modal`/`tabs` hits that do exist in the tree (e.g. `static_analysis/android_binary_analysis.html`, the iOS dynamic-analyzer pages) are pre-existing Bootstrap-era markup in legacy report pages the redesign hasn't touched — not a new design-system component.
- □ `drawer` — not built (a text hit in `auth/users.html` is incidental, not a real slide-in panel).
- □ `tabs` — not built (only present in the same untouched legacy iOS dynamic-analyzer pages noted under `modal`).
- □ `accordion` — not built.
- □ `disclosure` — not built.

## Data display

- ▣ `table` — real styled tables shipped (`rbac/audit_log.html`, `rbac/api_keys.html`, `general/recent.html`), the last with Django `Paginator` pagination plus client-side search/type filtering (see `pagination` below). No sortable headers, sticky header, or bulk-select checkbox.
- ■ `pagination` — `general/recent.html`: real `page_obj`/`Paginator`-driven page navigation and result counts, not a mock.
- ■ `badge` — `.badge` + severity variants (`critical/high/medium/low/passed/unknown`) in `app.css`.
  - ■ **`.badge-neutral`** (not on the original list, the newest token) — `bg-surface-2`/`text-secondary`, added to fix a real, systemic bug: the severity-badge classes above were being reused across 15+ templates for purely decorative/informational pills with zero severity meaning (item counts like "75 endpoints", version tags, feature labels). A green `badge-passed` pill next to an unrelated count reads as a false "this passed a security check" signal. `badge-neutral` is now the correct default for any label/count/tag that carries no real severity meaning.
- □ `tag` — not built.
- ▣ `pill` — `.mi-pillbtn` shipped (see Navigation/Utilities below) but that's a hero-CTA *button*, not the plain non-interactive label pill this line originally specified.
- ▣ `metric` — large-number-plus-delta-arrow stat tiles exist per page (`.mi-pill-delta`, `data-count-up`, e.g. `playground.html`, `general/recent.html`), but no sparkline, and no single shared `metric` include.
- □ `chart_line` — not built.
- □ `chart_bar` — not built as a Chart.js wrapper; the trend-chart role this was meant to fill is instead served by `dot_matrix` (below), which is not Chart.js at all.
- □ `chart_donut` — not built; no Chart.js dependency exists anywhere in the stack. The score-ring role this implies is served by `gauge_arc` (below).
- □ `chart_area` — not built.
- ■ `gauge` — **built, but not as specified — correcting a real inaccuracy in this doc.** This line originally said "half-donut for fleet health." What actually shipped (`mobinspect/templates/components/gauge_arc.html`) is a **270° full radial arc gauge**, not a half-donut (180°) at all. Mechanism, concretely: it's pure CSS/SVG with zero JS charting library and zero per-value backend trig. The arc track is an SVG `<circle>` with `pathLength="100"` + a `stroke-dasharray`/`stroke-dashoffset` trick to draw a partial ring. The value pointer (the small dot on the arc) gets its angle from **composing two CSS `rotate()` transforms** — an outer static `rotate(225deg)` frame (the arc's start angle) and an inner `rotate({% widthratio value 100 270 %}deg)` driven straight off Django's `{% widthratio %}` template tag — rather than any computed trig in Python or JS. Tick marks are fixed hardcoded coordinates (their angle doesn't depend on `value`). For any real security-score/severity use, callers must pass `color=value|score_color` (see `mi_score.py` below) — the fallback when no color is passed is the theme-aware "unknown" gray (`rgb(var(--score-unknown))`), not brand blue; that replaced a real bug where an uncalled `color=` previously silently rendered brand-blue, reading as a false severity signal.
- ▣ `code_block` — only the base `.code` inline-chip utility shipped (`app.css`); no syntax highlighting, copy button, or expand/collapse behavior.
- ■ `kbd` — `.kbd` utility class in `app.css`.
- ▣ `avatar` — a real initials-avatar pattern shipped in `auth/users.html` (`.mi-avatar`, tone cycled amber/violet/neutral, `w-8 h-8`) plus a separate avatar ring in the sidebar/topbar user menu — but as page-local patterns, not one shared component with the originally-specified xs/sm/md/lg size range.
- □ `progress_bar` — not built (one incidental text hit in an untouched legacy iOS page, not a real component).
- ■ `score_donut` — **built, but consolidated into `gauge_arc`, not a separate donut/ring.** This line and the `gauge` line above describe what became a single component: `gauge_arc.html` is used for both the general "gauge" case and the AppSec score display (`security_score|score_color` passed in as `color`). There is no second, separate ring-shaped score widget — don't read this as "two components," it's one, correctly parameterized.

## Feedback

- ▣ `toast` — a real `#mi-toasts` region is wired in `base/app.html` and renders Django's `messages` framework flashes with a fade-in + shadow on page load. It is not a JS-driven, client-triggerable stack with auto-dismiss-and-hover-pause — it only shows what the server put in the `messages` context at render time.
- □ `alert` — not built (only present in an untouched legacy iOS page).
- ▣ `empty_state` — a real dashed-border pattern shipped (`.mi-empty`, e.g. `rbac/permissions.html`, used for both a genuine Django `{% empty %}` case and a client-side "no search results" case), but as a per-page pattern rather than one shared include.
- ▣ `skeleton_text` / `skeleton_card` / `skeleton_table` — not split into three shaped variants as specified. A single generic `.skeleton` shimmer utility shipped in `app.css` (`bg-gradient-to-r ... animate-shimmer`), used in `general/tasks.html` and `playground.html`.
- ▣ `tooltip` — native `title="..."` attribute tooltips are used widely (e.g. per-column labels in `dot_matrix.html`, search inputs in `auth/users.html`). No Alpine-driven, positioned tooltip component.
- □ `popover` — not built.
- ▣ `confirm_dialog` — destructive actions are gated by a native browser `confirm()` (e.g. revoke API key and delete role in `rbac/api_keys.html` / `rbac/roles_list.html`), not a styled modal preset.

## Navigation

- ■ `sidebar` — `components/sidebar.html` + `components/sidebar_item.html`. Icon-only by default, with **real** `localStorage('mi-sidebar')` persistence — this is a full-page-reload Django app, not an SPA, so without persistence an expanded sidebar would silently re-collapse on every navigation; that was a real bug, found and fixed this session. Active-state color is brand blue (`.mi-nav-item.is-active`), not the amber/violet data-viz accent — a deliberate, separate identity decision (see Utilities note below). Its theme toggle stays in sync with the topbar's via the `mi:theme-change` window event.
- ■ `topbar` — `components/topbar.html`. Theme toggle (kept in sync with the sidebar's — see below), user avatar, and a `{% block breadcrumbs %}` hook. No notification bell or global search wired into it (see below).
- □ `breadcrumbs` — the `{% block breadcrumbs %}{% endblock %}` hook exists in `base/app.html`, but it's an empty placeholder — no page populates it, and there's no auto-generation logic behind it.
- □ `command_palette` — not built.
- □ `notification_bell` — not built.

### Utilities shipped this session that aren't on the original list at all

- ■ **`.mi-pillbtn`** — the dark grain-pill hero-CTA button (`#17181C` dark theme / `#1A1A1A` light theme), defined in `base/app.html`'s `#mi-chrome` style block. Convention: exactly one hero CTA per dashboard-style page.
- ■ **Theme system** — `mobinspect/static/mobinspect/js/theme.js`. Defaults to **dark** app-wide (was `'system'` before this session — the visual reference this redesign follows has no light variant, and the tool is meant for SOC-style daily use). Exists as two synced toggles (topbar + sidebar bottom group), kept in sync via the `mi:theme-change` `CustomEvent` — that event already existed in `theme.js` but was unused before this session; wiring both toggles to listen for it fixed a real cross-toggle desync bug (toggling in one place used to leave the other showing a stale icon).
- ■ **`mi_score.py` filter trio** (`mobinspect/MobInspect/templatetags/mi_score.py`) — `score_tier` / `score_color` / `score_class`, the single shared 0–100 security-score threshold (`<30` critical, `30–39` medium, `40–59` low, `>=60` passed). Before this existed, the same red/amber/blue/green ternary was hand-duplicated in 6 templates, and a 7th (`analytics/dashboard.html`) used a *different* 3-tier scale with no "low"/blue tier at all — so the same numeric score could render a different color depending which page you looked at it on. `gauge_arc.html` and every AppSec score display now source color from this filter instead.

## Domain-specific

- ■ `severity_badge` — not a distinct component, but the general `.badge-*` family (critical/high/medium/low/passed/unknown in `app.css`) *is* the real, shipped severity badge, applied wherever a genuine finding/status severity needs signaling. `.badge-neutral` (see Data display) is the enforced escape hatch for everything that isn't a real severity signal — that split was a real, systemic fix this session (severity badge classes had been reused for ~15+ purely decorative pills with no severity meaning).
- □ `role_badge` — not built as a distinct include; role display uses the color-swatch/icon system directly (see `color_picker`/`icon_picker`), not a packaged badge.
- □ `permission_chip` — not built as a distinct component; `rbac/permissions.html` and `rbac/role_form.html` render permission items with page-local markup.
- □ `app_card` — not built.
- □ `finding_row` — not built.
- ▣ `scan_status_pill` — scan status in `general/recent.html` is rendered via the general severity/badge family plus `data-type` row attributes (used for client-side filtering), not a dedicated pending/running/done/failed pill component.
- □ `cvss_vector` — not built.
- □ `cwe_link` — not built.
- □ `masvs_link` — not built.

## Layout primitives

- ▣ `page_header` — every redesigned page hand-rolls its own `<header>` (title + optional badge/CTA) in a consistent pattern, but there's no shared include, and no automatic breadcrumb wiring (see `breadcrumbs` above).
- □ `section_header` — not built as a distinct component.
- ▣ `divider` — a `.dot-sep::before` inline-separator utility exists in `app.css`; no full-width, optionally-labeled horizontal-rule component.
- □ `flex_row` — not packaged, and arguably doesn't need to be — plain Tailwind flex utilities are used ad hoc, which is Tailwind's normal usage pattern.
- ▣ `stat_strip` — real KPI-row patterns shipped per page (`analytics/dashboard.html`, `auth/users.html`, `general/recent.html`, `rbac/*`, `static_analysis/appsec_dashboard.html`, etc.), each with its own local `.mi-stat-*` CSS and amber/violet accent glows per the color policy below — but each page defines its own stat-tile styling rather than sharing one `stat_strip` include.

## Data-viz chart shipped this session, not on the original list

- ■ `dot_matrix` (`mobinspect/templates/components/dot_matrix.html`) — a dot-grid "skyline" chart: a column of filled/unfilled dots per data point, driven by a caller-supplied `max_value`. Takes **pre-zipped `(label, value)` tuples**, not two parallel lists — because Django template dot-lookup can't index a list by a loop-derived variable (`{{ values.idx }}` treats `idx` as a literal string key, not a resolved variable), the view has to `zip()` labels and values before passing them in, and the template unpacks with `{% for label, value in pairs %}`. It was also built while finding a second genuine template-engine bug: `{% widthratio %}` returns a *string*, so comparing `forloop.counter <= filled` silently evaluates false for every dot unless `filled` is coerced with `{{ filled|add:0 }}` to force a real int comparison.

## The three-tier color/button policy (context for the statuses above)

Worth stating plainly here since it's the thing most likely to look like an
unfinished or inconsistent sweep to someone unfamiliar with the reasoning,
and it explains several of the `■`/`▣` splits above:

1. **Brand blue** (`mobinspect` ramp, base `#2563EB`) = "operate the tool":
   sidebar, topbar, logo, nav active-state, the global focus-visible ring,
   `.btn-primary`, `.input` focus state. This is a deliberate, pre-existing
   identity decision, independent of the visual-reference mirror below.
2. **Amber/violet** (`chart.amber` / `chart.violet`) = dashboard data-viz
   content only — the gauge, `dot_matrix`, stat-tile accents, non-semantic
   icon chips. Never chrome, buttons, or body text.
3. **Dark grain-pill** (`.mi-pillbtn`) = the *one* hero CTA per
   dashboard-style page.
4. **Severity system** (`.badge-critical/high/medium/low/passed/unknown`) =
   semantic only, a real finding/status signal, never decoration —
   `.badge-neutral` is the safe default for anything that isn't one.

## Explicitly not built (intentional, not oversight)

`candlestick`/OHLC chart, flow/ribbon chart, compliance-percentage rows,
"Approve/Reject AI action" buttons — none of these have real MobInspect data
or a backing capability behind them (the last would imply live remediation
MobInspect doesn't do), so they weren't faked with placeholder data just to
check a box.

## Implementation order

This was the original planned build order, phased against a "Phase 2 page
rollout" that this doc predates. It's kept here for the record, but it is
**not** what actually happened: the real work this session followed a
CSS-utility-first path (extend `app.css`'s `@layer components` and reuse
those classes directly in markup) plus a small number of genuinely reusable
includes for the highest-leverage widgets (`gauge_arc`, `dot_matrix`,
`sidebar`/`sidebar_item`, `topbar`, `logo_mark`) — not a page-by-page march
through the phases below. Treat this list as historical intent, not a status
report; the per-item statuses above are the source of truth for what's real.

1. **Phase 0**: button, input, card, badge, lucide tag, theme toggle, toast — enough to render the playground
2. **Phase 1**: table, modal, confirm_dialog, tooltip, alert, role_badge, permission_chip, color/icon pickers — for the RBAC admin
3. **Phase 2.1**: sidebar, topbar, breadcrumbs, page_header, alert, empty_state, skeleton_*
4. **Phase 2.2**: tabs, drawer, code_block, severity_badge, finding_row, score_donut, scan_status_pill
5. **Phase 2.3**: app_card, accordion, cvss_vector, cwe_link, masvs_link
6. **Phase 2.4**: chart_*, gauge, metric, stat_strip
7. **Phase 2.5**: command_palette, notification_bell, popover, file_upload (refresh)
