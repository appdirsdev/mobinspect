# 04 — Design System

> The visual + interaction language for MobInspect. Tokens are enforced by `tailwind.config.js` and the CSS custom properties in `mobinspect/static/mobinspect/css/src/app.css`; component behavior lives in `mobinspect/templates/components/` and the `#mi-chrome` style block in `mobinspect/templates/base/app.html`. This doc is the prose reference for *why* things are the way they are — for the punchier one-page "tiebreaker" version see `docs/design/mood.md`, for the raw token export see `docs/design/tokens.json`, and for the (partly aspirational, phase-tracked) full component checklist see `docs/design/component-inventory.md`.

## Where this comes from

The visual direction is not open-ended taste. It's modeled on a Behance case study, *"Cyber Security UI/UX Design"*, for a fictional product called **CyberGuard**. The palette hex codes (the amber/violet duotone) and the Albert Sans display typeface came directly off that reference's own style-guide and type-specimen slides — this was a client-material-pinned brief, not a "find something that looks cool" exercise. That matters for how you should treat deviations from it: a deviation needs a reason, not a preference.

One thing was deliberately **not** inherited from CyberGuard: the brand blue used for the sidebar, topbar, logo, and every interactive control. That's MobInspect's own product identity — the "M" monogram logo and blue ramp predate this visual pass and were kept as a considered, separate decision, layered on top of the CyberGuard mirror rather than replaced by it. If you're new to the codebase and the palette looks like two different design systems bolted together, that's an accurate read of the history, but it's intentional, not unfinished — see "The three-tier color/button policy" below, which exists specifically to answer that question.

## Design principles

1. **Information dense, never noisy** — security analysts triage hundreds of findings; whitespace is a tool, not a goal.
2. **Severity is the primary signal** — color hierarchy always serves risk communication first. Nothing decorative is allowed to compete with a real severity color for attention.
3. **Dark by default** — analysts work long shifts; dark UIs are kinder over hours, and the reference product (CyberGuard) has no light variant at all. Light mode is fully supported, it's just not what greets you (see "Theme" below).
4. **Motion is functional** — every animation must answer "what just happened?" or "what can I do here?" Decoration-only motion is forbidden.
5. **Keyboard-first** — every action reachable in ≤3 keystrokes; visible focus rings always.
6. **Honest empty states, honest scope** — never show empty tables without explanation, and never build a UI element that implies data or capability MobInspect doesn't actually have (see "What was deliberately not built" below).

## THE THREE-TIER COLOR/BUTTON POLICY

This is the single most important section in this document. Read it before touching any color or button variant. If you only remember one thing from this file, remember this: **every color in the product answers to exactly one of three tiers, plus a fourth rule that sits outside the tier system entirely (severity).** Nothing freelances. A future reader encountering blue chrome next to an amber/violet dashboard next to a near-black CTA button next to red/orange/blue severity badges could reasonably suspect an unfinished or inconsistent sweep — it is neither. It's a considered three-way split plus one hard semantic rule, and here is the reasoning for each:

1. **Brand blue (`mobinspect` ramp, base `#2563EB`) = "operate the tool."** Sidebar, topbar, logo, the global focus-visible ring (`*:focus-visible` in `app.css`, applied to every interactive element), `.btn-primary`, and `.input` focus border/ring. This is chrome — the controls you use to drive the product — not data. It's a pre-existing, separate identity decision from the CyberGuard mirror: MobInspect's monogram and blue ramp predate this visual pass and were kept deliberately rather than overwritten to match the reference exactly. **Exception — nav active-state is NOT part of this tier.** `.mi-nav-item.is-active` was originally blue (`#2563EB` light / `#60A5FA` dark) as part of this same "separate identity" reasoning. A later pixel-level check against the actual reference (`Dashboard.png`, sampled directly with PIL rather than judged by eye) found the real active-state indicator is a neutral dark charcoal chip, not blue — so this one piece of chrome was pulled back into the fidelity mirror and now reuses the CTA pill's dark-neutral fill (`#17181C` / `#1A1A1A`, tier 3 below) instead. This reverses an earlier, explicitly-confirmed decision; noted here so the reversal reads as deliberate, not an oversight.
2. **Amber/violet duotone (`chart.amber #FE4A23`, `chart.violet #8D5CFC`) = dashboard data-visualization content only.** Gauge fill, chart series, stat-tile accent bars/glows, non-semantic icon chips. Sourced directly from the CyberGuard reference. It must **never** appear on a button, a nav item, or body text — the moment amber shows up on something clickable, it starts competing with brand blue for "what do I click," and the dashboard stops reading as calm instrumentation and starts reading as a Christmas tree. See "Chart duotone and its WCAG caveat" below for the contrast-ratio detail that makes this restriction load-bearing, not stylistic.
3. **The dark grain-pill CTA (`.mi-pillbtn`, `#17181C` dark theme / `#1A1A1A` light theme) = exactly one hero action per dashboard-style page.** This mirrors CyberGuard's own screens, which never show two primary CTAs competing for attention on one dashboard. If you're adding a second `.mi-pillbtn` to a page that already has one, that's very likely a downgrade to `.btn-primary` (brand blue) instead, not a second pill.
4. **Severity = semantic only, never decoration — and this rule sits outside the three tiers above, not alongside them.** A `badge-critical`/`badge-high`/`badge-medium`/`badge-low`/`badge-passed`/`badge-unknown` color must correspond to a real scan-finding severity or connection/status health value: a VirusTotal detection ratio, a tracker-count-vs-threshold, a permission protection-level, an audit-event risk category. It is never allowed to mean "this row is exciting" or "this label needs a pop of color." This exact rule was being broken in the wild before this session — see "`badge-neutral`" below — which is precisely why it's written down here in plain terms rather than left implicit.

If you're choosing a color for something new, ask "which of these four buckets is this?" first. If the honest answer is "none, I just want it to look nice," the correct color is a neutral one (`badge-neutral`, `text-secondary`, a surface token) — CyberGuard's own screens are calm specifically because almost everything on them is neutral, and the handful of accented elements read as meaningful *because* they're rare.

## Color tokens

Source of truth: `tailwind.config.js` for static Tailwind color classes, and the `--*` CSS custom properties in `mobinspect/static/mobinspect/css/src/app.css`'s `@layer base` (`:root`/`[data-theme='light']` and `[data-theme='dark']` blocks) for anything that needs to resolve per-theme inside an inline `style=` attribute (SVGs, the gauge) where Tailwind's `dark:` class variant mechanism can't reach. Colors are expressed as bare `R G B` triplets so Tailwind's `rgb(var(--token) / <alpha-value>)` mechanism can apply alpha on top.

### Brand ramp (`mobinspect`, 50–950)

```
mobinspect.500   #2563EB  ─ base / primary CTA, .btn-primary, focus ring
mobinspect.400   #3B82F6  ─ links, hover lift, nav active-state icon glow
mobinspect.600   #1D4ED8  ─ active / pressed
mobinspect.50    #EFF6FF  ─ subtle highlights (light theme)
mobinspect.950   #172554  ─ deepest accent (dark theme)
```

Full ramp: 50 `#EFF6FF`, 100 `#DBEAFE`, 200 `#BFDBFE`, 300 `#93C5FD`, 400 `#3B82F6`, 500 `#2563EB`, 600 `#1D4ED8`, 700 `#1E40AF`, 800/900 `#1E3A8A`, 950 `#172554`. This is the "operate the tool" color — see tier 1 of the policy above. Nav active-state does **not** use this ramp — see the tier-1 exception note above; `.mi-nav-item.is-active` uses the CTA pill's dark-neutral fill (`#17181C` / `#1A1A1A`) instead, corrected after pixel-sampling the reference.

### Chart duotone — data-visualization only

| Token | Hex | Use |
|-------|-----|-----|
| `chart.amber` | `#FE4A23` | Primary data series: gauge fill, bar/line strokes, stat-tile accent |
| `chart.violet` | `#8D5CFC` | Secondary data series: alternating bars, contrast line, secondary stat accent |

Reserved **exclusively** for gauge fill, chart series, stat-tile accent bars/glows, and non-semantic icon chips (icon chips that decorate a UI element but don't signal severity or status). Never buttons, never nav, never body text, never UI chrome. See tier 2 of the policy above for why this restriction exists, and the WCAG note directly below for the mechanical reason body-text usage specifically is off the table.

**Chart duotone and its WCAG caveat**: both `chart.amber` and `chart.violet` fail the 4.5:1 contrast ratio required for body text (`#FE4A23` on white = 3.38:1, `#8D5CFC` on white = 4.14:1, `#8D5CFC` on dark surfaces = 3.84:1). Both colors do clear the 3:1 threshold WCAG allows for large text and non-text/graphical objects, so icon-glyph and large-display numeral usage (e.g. the gauge's center number, if ever recolored) is fine — but using either color for a sentence of body copy is a real accessibility failure, not a style nitpick. A tree-wide audit for stray body-text usage of the chart duotone ran the same session this token set was introduced.

### Severity (semantic only — see tier 4 of the policy above)

| Token | Light hex | Dark hex | Signals |
|-------|-----------|----------|---------|
| `severity.critical` | `#DC2626` | `#F87171` | Real critical finding (e.g. CVSS 9.0+, malware confirmed) |
| `severity.high` | `#EA580C` | `#FB923C` | High-severity finding |
| `severity.medium` | `#D97706` | `#FBBF24` | Medium-severity finding |
| `severity.low` | `#2563EB` | `#60A5FA` | Low-severity / informational finding |
| `severity.passed` | `#16A34A` | `#4ADE80` | Check passed, no finding |
| `severity.unknown` | `#64748B` | `#94A3B8` | Undetermined, suppressed, or not yet evaluated |

Each severity has a matching `.badge-*` class in `app.css` (`.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-passed`, `.badge-unknown`), each built as a light background tint + matching text color, theme-aware via `dark:` variants. **Rule**: a severity color/badge must always correspond to a real severity or status signal — VirusTotal detection ratio, tracker-count-vs-threshold, permission protection-level, audit-event risk category, connection health — and never decoration. A "Save" button is brand blue, never `severity.low`'s blue. A generic success toast is `system.success`, never `severity.passed`, even though the two currently share a hex value (see System below) — they're semantically distinct even when visually identical, because one can change independently of the other later.

### `badge-neutral` — the safe non-severity default

```css
.badge-neutral { @apply bg-surface-2 text-text-secondary; }
```

The newest badge variant, added this session to fix a real, systemic bug: severity-badge classes (`badge-critical`/`badge-high`/`badge-medium`/`badge-low`/`badge-passed`/`badge-unknown`) had been reused across 15+ templates as a free color palette for pills that carry **zero** severity meaning — item counts ("75 endpoints", "4 categories"), version tags, feature labels, file-type tags. A green `.badge-passed` pill sitting next to an unrelated feature label reads as a false "this passed a security check" signal, whether or not that was the intent. `.badge-neutral` (surface-2 background, secondary text color) is the correct default for any label, count, or tag that doesn't carry a real severity or status meaning. If you're reaching for a `.badge-*` class and the thing you're labeling isn't a genuine finding or status, reach for `.badge-neutral`, not a severity color that merely "looks fine."

### System (interactive states)

| Token | Light hex | Dark hex | Use |
|-------|-----------|----------|-----|
| `system.success` | `#16A34A` | `#4ADE80` | Toasts, badges, "OK" states |
| `system.warning` | `#D97706` | `#FBBF24` | Soft warnings, deprecation notices |
| `system.error` | `#DC2626` | `#F87171` | Validation errors, destructive confirmation, `.btn-danger` |
| `system.info` | `#2563EB` | `#60A5FA` | Tips, contextual help |

These intentionally mirror the hex values of `severity.passed` / `severity.medium` (⇒ mapped to warning) / `severity.critical` / `severity.low` respectively — same colors, different semantic layer (UI/interaction state vs. scan-finding severity). Keep them as separate token names even though the values currently match; a UI state color changing independently of the severity scale (or vice versa) is a real future possibility this separation protects against.

### CTA black — `.mi-pillbtn`

```
#17181C   dark theme
#1A1A1A   light theme
```

Defined in `mobinspect/templates/base/app.html`'s `#mi-chrome` style block (not in `app.css`), because it was promoted from a single page (`general/home.html`) to a global utility class this session. See tier 3 of the policy above for the "one hero CTA per page" convention, and "Glass + pill utilities" below for the full implementation detail.

### Score tiers — one canonical threshold scale

**This is the single source of truth for any score → color mapping in the product. Do not hand-write the `<30`/`<40`/`<60`/else ternary in a template again — this exact mistake was made independently 7 times before this session fixed it.**

Before `mobinspect/MobInspect/templatetags/mi_score.py` existed, 7 different templates each hand-duplicated a security-score-to-color threshold ternary, and one of them — the analytics dashboard — used a *completely different* 3-tier scale with no "low"/blue tier at all. The practical consequence: the exact same numeric score (say, 45) could render as one color on a per-app static analysis report and a visually different color on the analytics dashboard, purely because of which template happened to implement the ternary. That's not a cosmetic inconsistency in a security tool — it actively misrepresents risk to whoever's reading the score.

The fix is one canonical scale, defined once:

```
score <  30              → critical
30 <= score <  40         → medium
40 <= score <  60         → low
score >= 60               → passed
```

This matches the majority pre-existing scale (the one `appsec_dashboard.html` and per-app static-analysis reports already used) — the analytics dashboard's divergent scale was the one that got conformed, not the other way around.

Exposed two ways, both driven from the same thresholds:

1. **CSS custom properties**, theme-aware, in `mobinspect/static/mobinspect/css/src/app.css`'s `@layer base` — `--score-critical`, `--score-medium`, `--score-low`, `--score-passed`, `--score-unknown` (light + dark blocks). These mirror the `severity-*` tokens' exact hex pairs; they exist as a separate CSS-var family (rather than reusing `--severity-*` directly) specifically so an inline `style="color: ..."` attribute — e.g. the gauge's SVG, which can't use Tailwind's `dark:` class variant — can still resolve the right shade per theme.
2. **Three Django template filters**, in `mobinspect/MobInspect/templatetags/mi_score.py`, loaded via `{% load mi_score %}`:
   - `score_tier` → returns the bare tier name (`'critical'`/`'medium'`/`'low'`/`'passed'`, or `''` if the value is `None`/non-numeric — it fails closed to "no tier" rather than guessing).
   - `score_color` → returns a ready-to-use CSS color value, `rgb(var(--score-<tier>))`, for inline `style=` usage (this is what `gauge_arc.html` requires — see below).
   - `score_class` → returns Tailwind utility classes, `text-severity-<tier> dark:text-severity-<tier>-dark`, for callers that want to color a text element via class rather than inline style.

Usage in any template that displays a security score:

```django
{% load mi_score %}
<span style="color: {{ security_score|score_color }}">{{ security_score }}</span>
{# or, for a class-based element: #}
<p class="{{ security_score|score_class }}">{{ security_score }}</p>
```

If you ever find yourself writing `{% if score < 30 %}...{% elif score < 40 %}...{% endif %}` in a template again, stop — that logic already exists once, correctly, in `mi_score.py`. Add a filter call instead.

### Surfaces (depth)

Five surface levels convey hierarchy, each with a paired border token. CSS custom properties, `[data-theme]`-toggled, defined in `app.css`.

| Token | Light | Dark | Use |
|-------|-------|------|-----|
| `surface.0` | `#FFFFFF` | `#0B0F1A` | App canvas / page background |
| `surface.1` | `#F8FAFC` | `#111827` | Card / panel background |
| `surface.2` | `#F1F5F9` | `#1F2937` | Nested card, hovered row, `.badge-neutral` background |
| `surface.3` | `#E2E8F0` | `#374151` | Sidebars, footers, code blocks |
| `surface.4` | `#CBD5E1` | `#4B5563` | Modals, drawers, popovers |
| `border.subtle` | `#E2E8F0` | `#1F2937` | Divider lines |
| `border.default` | `#CBD5E1` | `#374151` | Card borders |
| `border.strong` | `#94A3B8` | `#6B7280` | Form input borders |

In dark mode, hierarchy leans on these surface deltas and borders rather than shadows — shadows read as visually weak once the page background is already dark, so don't reach for a heavier `shadow-elevation-*` to fix a dark-mode hierarchy problem; reach for the next surface step up instead.

### Text

| Token | Light | Dark | Use |
|-------|-------|------|-----|
| `text.primary` | `#0F172A` | `#F1F5F9` | Headings, body |
| `text.secondary` | `#475569` | `#94A3B8` | Labels, metadata |
| `text.tertiary` | `#94A3B8` | `#64748B` | Disabled, placeholder |
| `text.inverse` | `#F8FAFC` | `#0F172A` | On colored backgrounds |
| `text.brand` | `#1D4ED8` (mobinspect.600) | `#3B82F6` (mobinspect.400) | Links |

### Theme switching

Implemented with Tailwind's class-based dark mode (`darkMode: ['class', '[data-theme="dark"]']` in `tailwind.config.js`), toggled via `data-theme="dark"|"light"` on `<html>`. State lives in `localStorage['mi-theme']` with three possible stored values — `'light'`, `'dark'`, `'system'` — managed by `mobinspect/static/mobinspect/js/theme.js` (`window.MI.theme`).

**Default is now `'dark'`**, not `'system'`. This was a deliberate change this session: the CyberGuard reference has no light variant at all, and the dashboard is meant for SOC-style daily use where a shift-long dark UI is kinder than one that flips based on OS preference. Light mode remains fully built and supported — it's reachable via the toggle — it's just no longer what greets a first-time or no-preference user. The `get()` function in `theme.js` and the no-flicker inline bootstrap script (in `mobinspect/MobInspect/templatetags/theme.py`, run at the very top of `<head>` before paint) must stay in sync on this default; they're two separate places that both encode "default is dark" and a future change to one without the other would reintroduce flicker or a mismatched default.

**Two toggles, one event.** The theme toggle exists in two places in the UI — the topbar and the sidebar's bottom group — and both need to reflect the current theme and stay in sync with each other. This is done via a `mi:theme-change` `CustomEvent` dispatched on `window` by `theme.js`'s `apply()` whenever the theme changes (detail: `{ value, effective }`). `sidebar.html` and `topbar.html` both listen for it (`@mi:theme-change.window="pref = $event.detail.value"`), as does the Chart.js theming wrapper (`chart-theme.js`) so charts recolor without a page reload. The event itself already existed in `theme.js` before this session but nothing was listening for it — wiring both toggles (and the chart wrapper) to it fixed a real cross-toggle desync bug where clicking the topbar toggle wouldn't update the sidebar toggle's displayed state, and vice versa.

## Typography

### Type stack

```
Display/headings:  "Albert Sans" (self-hosted, variable, SIL OFL license)
UI / Body:         "Inter" (self-hosted, variable), system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
Code/data:         "JetBrains Mono" (self-hosted, variable), ui-monospace, "Cascadia Code", Menlo, monospace
```

**Albert Sans is applied via an explicit CSS override, not through `tailwind.config.js`.** Tailwind v3's `fontSize` array-shorthand config (`fontSize: { display: ['48px', { lineHeight, fontWeight }], ... }`) has no `fontFamily` key — this was verified empirically: a `fontFamily` key added to that config object is silently dropped from the compiled CSS output, with no build warning. Because of that, the display face is instead set directly in `app.css`'s `@layer utilities`:

```css
.text-display, .text-h1, .text-h2, .text-h3, .text-h4 {
  font-family: 'Albert Sans', theme('fontFamily.sans');
}
```

So `tailwind.config.js`'s `fontSize` entries for `display`/`h1`–`h4` only carry size/line-height/weight; the font-family swap is layered on top in `app.css`. If you're adding a new heading-scale utility, remember it needs to be added to that selector list too, or it'll silently render in Inter instead of Albert Sans.

Body and UI text intentionally stays on **Inter**, not Albert Sans, at small sizes — this was a deliberate legibility call, not an oversight: Albert Sans is a display-personality face, and personality faces get harder to read at 13–14px in a data-dense tool you're staring at for a security triage session. Albert Sans is used with restraint (headings and large numerals only), not applied wholesale just because it was available.

**JetBrains Mono** is unchanged from before this session — hashes, code, technical values (permission names, package IDs), and any tabular figures.

All three are self-hosted under `mobinspect/static/mobinspect/fonts/` as variable-weight WOFF2 files with `font-display: swap`, declared via `@font-face` in `app.css`'s `@layer base`.

### Type scale (1.25 modular)

| Token | Size | Line height | Weight | Typeface | Use |
|-------|------|-------------|--------|----------|-----|
| `text-display` | 48px | 1.1 | 700 | Albert Sans | Hero numbers (e.g. the gauge's center score) |
| `text-h1` | 30px | 1.2 | 600 | Albert Sans | Page titles |
| `text-h2` | 24px | 1.25 | 600 | Albert Sans | Section headings |
| `text-h3` | 20px | 1.3 | 600 | Albert Sans | Card titles |
| `text-h4` | 16px | 1.4 | 600 | Albert Sans | Subsections |
| `text-body` | 14px | 1.55 | 400 | Inter | Default body |
| `text-small` | 13px | 1.5 | 400 | Inter | Metadata, captions |
| `text-tiny` | 12px | 1.4 | 500 | Inter | Badges, table headers (uppercase, `tracking-wide`, `letter-spacing: 0.05em`) |
| `text-mono` | 13px | 1.5 | 400 | JetBrains Mono | Code, hashes, file paths |

## Spacing (4px base)

Tailwind defaults: `0.5 / 1 / 2 / 3 / 4 / 6 / 8 / 12 / 16 / 24` map to `2px / 4px / 8px / 12px / 16px / 24px / 32px / 48px / 64px / 96px`.

**Layout grid**, defined via `tailwind.config.js`'s `spacing`/`maxWidth` extensions:
- Sidebar: `240px` expanded (`spacing.sidebar`), `64px` collapsed (`spacing['sidebar-collapsed']`)
- Topbar: `56px` tall (`spacing.topbar`)
- Main content: `max-width: 1440px` (`maxWidth.content`), padded `px-6` desktop, `px-4` tablet
- Card grid gap: 16px (`gap-4`)

## Border radius

| Token | Value | Use |
|-------|-------|-----|
| `rounded-sm` | 4px | Inputs, small badges |
| `rounded-md` | 6px | Buttons |
| `rounded-lg` | 8px | Cards, panels |
| `rounded-xl` | 12px | Modals |
| `rounded-2xl` | 16px | Hero panels (sparingly) |
| `rounded-full` | — | Pills, avatars, `.mi-pillbtn`, badges |

## Shadows / elevation

Four elevation levels plus a focus/brand glow, defined in `tailwind.config.js`'s `boxShadow` extension:

```
elevation-1:    0 1px 2px rgb(0 0 0 / .05)
elevation-2:    0 4px 8px -2px rgb(0 0 0 / .08), 0 2px 4px -2px rgb(0 0 0 / .04)
elevation-3:    0 12px 24px -8px rgb(0 0 0 / .12), 0 4px 8px -4px rgb(0 0 0 / .06)
elevation-4:    0 24px 48px -12px rgb(0 0 0 / .18)
elevation-glow: 0 0 0 4px rgb(37 99 235 / .15)   // focus ring + active brand
```

As noted under Surfaces above: in dark mode, prefer moving up a surface level or adding a border over reaching for a heavier shadow — shadows read as visually weak once the background itself is already dark, so `elevation-4` on a dark card won't buy you the hierarchy that `elevation-2` buys you on a light one.

## Glass + pill utilities

Both defined in `mobinspect/templates/base/app.html`'s `#mi-chrome` `<style>` block (not `app.css`) — they started as page-specific styling on `general/home.html` and were promoted to global, reusable classes this session.

### `.mi-glass`

```css
.mi-glass {
  background: rgb(var(--surface-1) / 0.6) !important;
  backdrop-filter: blur(16px) saturate(150%);
  -webkit-backdrop-filter: blur(16px) saturate(150%);
  border-color: rgb(var(--border-subtle) / 0.5) !important;
}
```

A translucent, frosted card surface. **Opt-in per element** via `class="card mi-glass"` — added alongside `.card`, not replacing it — and deliberately **not** forced onto the base `.card` class app-wide. Dense tables and forms intentionally stay fully opaque: translucency under a data table you're scanning for a security triage is a readability tax nobody asked to pay. Reach for `.mi-glass` on dashboard-style hero cards and stat panels, not on anything with dense tabular or form content. There's also a `@supports not (backdrop-filter)` fallback that swaps to a near-opaque flat background for browsers without backdrop-filter support.

### `.mi-pillbtn`

```css
.mi-pillbtn {
  background: #17181C;  /* #1A1A1A in light theme, via [data-theme="light"] override */
  color: #fff;
  border-radius: 9999px;
  /* + a subtle fractal-noise grain overlay at ~7% opacity, mix-blend-mode: overlay */
}
```

The dark grain-pill hero CTA — CyberGuard's own "Check Alerts" button treatment: a neutral near-black pill with a faint noise texture (not brand-colored). Applied as `class="btn ... mi-pillbtn"` alongside the normal `.btn` sizing classes. Convention (tier 3 of the color policy above): **exactly one** `.mi-pillbtn` per dashboard-style page — it's the one hero action, and a second pill on the same page dilutes that. Every other primary action on the page should be `.btn-primary` (brand blue) instead. The grain overlay is capped low enough in opacity (~2% effective contribution) that it doesn't measurably affect text contrast.

## Signature component — the radial gauge (`mobinspect/templates/components/gauge_arc.html`)

The 270° arc score meter is the component every scan report leads with, and it's built with a genuinely small piece of engineering rather than a dropped-in chart-library widget: **pure CSS/SVG, zero JS charting dependency, zero per-value backend trigonometry.**

- The **pointer dot's angle** comes from composing two nested CSS `rotate()` transforms (`.mi-gauge-pointer-frame` fixed at `rotate(225deg)`, `.mi-gauge-pointer-inner` rotated by the value-driven angle) — the value-driven rotation itself is computed entirely in the template via Django's `{% widthratio value 100 270 %}deg`, so there's no Python-side trig, no JS animation library, just one arithmetic tag and two composed CSS transforms.
- The **arc track** uses an SVG `pathLength="100"` + `stroke-dasharray` trick: setting `pathLength="100"` on the `<circle>` lets `stroke-dasharray` be expressed directly in "percent of arc" units regardless of the circle's actual pixel radius, so the fill amount is just `{% widthratio value 100 75 %} 100` (75, not 100, because the track is a 270°/360° = 75% sweep).
- **Tick marks are fixed literals** — their coordinates don't depend on `value` (they mark 0/25/50/75/100 on a static 270° dial), so they're hardcoded `<line>` elements rather than computed.

**Color contract**: the gauge takes a `color` param that must be a CSS color value. For any security-score/severity use, callers **must** pass `color=value|score_color` (which requires `{% load mi_score %}` in the including template) — never a bare hex, and never omit it expecting a sensible default. The one shared threshold source is `mi_score.py` (see "Score tiers" above), so routing every gauge through `score_color` is what guarantees the same numeric score renders the same color everywhere the gauge appears.

**The fallback color is a real bug fix, not a stylistic choice.** When `color` isn't supplied, the gauge now falls back to `rgb(var(--score-unknown))` — the theme-aware "unknown severity" gray — not brand blue. Previously, an uncalled `color=` argument silently rendered brand blue, which is actively misleading on a component whose entire job is communicating severity: gray-for-unknown honestly says "no severity color was supplied," while blue-for-unknown looked like a real (if oddly-colored) status. This was found and fixed this session.

## Dot-matrix chart (`mobinspect/templates/components/dot_matrix.html`)

A dot-grid "skyline" chart: takes pre-zipped `(label, value)` tuples plus a caller-computed `max_value` and `unit`, and renders a column of filled/unfilled dots per data point (6 dots per column, filled bottom-up proportional to `value / max_value`). Built while finding and fixing two genuine Django template-engine bugs, both worth knowing about since they're easy to reintroduce:

1. **You cannot index a list by a loop-derived variable via dot-lookup.** `{{ values.idx }}` inside a `{% for idx in ... %}` loop treats `idx` as a *literal string key* against `values`, not as a resolved variable — Django's template dot-lookup doesn't do variable-subscript resolution the way Python's `values[idx]` does. The correct pattern is for the backend view to pre-zip `(label, value)` pairs (`zip(labels, values)`) and have the template unpack them directly: `{% for label, value in pairs %}`. This is why `dot_matrix.html`'s contract requires a `pairs` param rather than two parallel `labels`/`values` lists.
2. **`{% widthratio %}` returns a string, not an int.** Comparing `forloop.counter <= filled` where `filled` came from `{% widthratio value max_value 6 as filled %}` silently evaluates false for every iteration — not an error, just wrong output, every dot renders empty regardless of the real value — unless `filled` is coerced to a real int first via the template arithmetic filter `{{ filled|add:0 }}`. The component's actual comparison is `{% if forloop.counter <= filled|add:0 %}`.

## Sidebar / navigation

Icon-only by default, expandable, with **real `localStorage` persistence** (key: `'mi-sidebar'`, read in `sidebar.html`'s Alpine `x-data` as `(localStorage.getItem('mi-sidebar') ?? 'collapsed') !== 'expanded'`). This matters specifically because MobInspect is a full-page-reload Django app, not an SPA — without persisting the expand/collapse state, an expanded sidebar would silently re-collapse on every single navigation, since each page load is a fresh DOM with no client-side router to preserve state across. That's not a nice-to-have; it was a real bug, found and fixed this session.

Active-state color is a neutral dark-charcoal chip (`#17181C` dark theme / `#1A1A1A` light theme via `.mi-nav-item.is-active`, reusing the CTA pill's fill) — not the amber/violet dashboard duotone, and, as of a pixel-level fidelity check against `Dashboard.png`, not brand blue either. Navigation stays chrome, not data-visualization content (consistent with the rest of tier 1), but the specific active-state color was corrected to match what the reference actually shows once verified directly rather than assumed. See the tier-1 exception note above for the full reasoning.

Theme toggle exists in two places — topbar and the sidebar's bottom group — kept in sync via the `mi:theme-change` window event (see "Theme switching" above for the full story on that fix).

## Motion

Powered by **Motion One**. Durations and easings are defined once in `tailwind.config.js` (`transitionDuration`/`transitionTimingFunction`) and referenced by name, not re-specified per component:

```js
duration: { fast: 120, base: 200, slow: 320 }   // ms
easing: {
  out:    'cubic-bezier(0.16, 1, 0.3, 1)',     // ease-out-expo, default
  in:     'cubic-bezier(0.7, 0, 0.84, 0)',
  'in-out':'cubic-bezier(0.65, 0, 0.35, 1)',
}
```

### Motion patterns

| Pattern | When | Duration / easing |
|---------|------|-------------------|
| **Page transition** | Route change | `200ms / out` — fade + 4px slide-up |
| **Card reveal** | Cards mount above the fold | `320ms / out`, stagger 50ms |
| **Hover lift** | Card / button hover | `120ms / out` — `translateY(-1px)` + elevation up |
| **Modal in** | Open dialog | Backdrop fade `200ms`; panel scale 0.95→1 + fade `200ms / out` |
| **Toast in** | Notification | Slide from top-right + fade `200ms / out` |
| **Chart mount** | Chart enters viewport | Bars/lines draw `slow / in-out`, 80ms stagger |
| **Gauge draw-in** | Gauge mounts | `mi-gauge-draw`, `1.2s .15s cubic-bezier(.16,1,.3,1)`, animates `stroke-dashoffset` from the arc's own length to 0 |
| **Severity pulse** | New critical finding | 2 pulses then stop — never infinite |
| **Skeleton shimmer** | Loading | 1.5s linear loop, gradient sweep (`animate-shimmer`) |

### Always

- Respect `prefers-reduced-motion: reduce` — `app.css` drops all `animation-duration`/`transition-duration` to `80ms` and disables smooth scroll globally under this media query; `.mi-pillbtn`'s hover transform is separately disabled under the same query.
- Never animate during text entry.
- Never animate scroll-jacking; native scroll only.

## Iconography

**Lucide** icons rendered as inline SVG via a template tag. Stroke width fixed at `1.5`. Color always `currentColor`, so icon color inherits from whatever text-color context it's placed in (severity text, brand text, secondary text) rather than being set independently — this keeps icon and adjacent-label color from drifting out of sync.

## Accessibility

- **WCAG 2.1 AA** color contrast is the target for all body text. The one documented, deliberate exception is the chart duotone (`chart.amber`/`chart.violet`), which clears the 3:1 non-text/graphical-object threshold but not the 4.5:1 text threshold — see "Chart duotone and its WCAG caveat" above. That's why the duotone is restricted to icon glyphs, chart marks, and large-display numerals, never sentence-level body copy.
- Visible focus ring on every interactive element (`*:focus-visible` in `app.css`, brand-blue `mobinspect.500`, `2px` with `2px` offset) — this is the one place brand blue appears purely for accessibility rather than "operate the tool" chrome, and it's consistent with tier 1 since focus state is itself a form of tool-operation feedback.
- All form inputs have associated `<label>`s (`.label` class).
- Modals trap focus and restore it on close.
- Live regions for toasts (`aria-live="polite"`) and errors (`aria-live="assertive"`).
- Tables use `<th scope="col">` and announce sort state.
- Dark/light toggle is keyboard-accessible and announces state.

## What was deliberately not built

Several dashboard elements that would look impressive were intentionally left out, because MobInspect doesn't have real data or backing capability for them, and a good-looking dashboard that implies capability the product doesn't have is worse than a plainer one that's honest about its limits:

- **Candlestick/OHLC chart** — no financial/time-series data of that shape exists in the product.
- **Flow/ribbon chart** — no flow-relationship data to visualize.
- **Compliance-percentage rows** — no compliance-framework scoring backend exists yet.
- **"Approve/Reject AI action" buttons** — would imply live remediation capability MobInspect doesn't have; the LLM enrichment feature (see the AI Dashboard work) is read-only analysis, not an actuator.

If a future page seems to call for one of these, that's a signal to build the backing data/capability first, not to fake the UI around data that doesn't exist.

## Rollout coverage and how the sweep was verified

47 templates were visually swept this session (adding `.mi-glass` cards, amber/violet data-viz accents, and pill CTAs where applicable) on top of the already-shipped `general/home.html`, via an adversarial two-stage pipeline: one agent designs each file, then a second, independent agent verifies it by diffing against a pre-edit baseline snapshot and checking a hard checklist (Django blocks/URLs/icons/template vars preserved, no fabricated data, severity colors left untouched, etc.).

Of the 47 files, 9 were initially flagged by the verify stage. Each was individually investigated rather than trusted at face value, since a flag is a hypothesis, not a verdict:
- **6 were false alarms** caused by a timing bug in the verification harness itself — the "pre-edit" baseline snapshot had actually been captured *after* the edit in those 6 cases, so the diff had nothing valid to compare against. Confirmed harmless via an independent `git diff` against `HEAD` plus a template-compile check on each of the 6.
- **1 was a real bug**: severity-badge classes reused for decorative, non-severity content — this is the finding that led to `.badge-neutral` (see above), and it turned out to be systemic well beyond the one flagged file: roughly 15 files needed the same fix once it was searched for tree-wide.
- **1 was legitimate-but-out-of-scope logic drift**: a template had swapped a custom `key` template filter for plain Django dot-notation inside a data-access loop. Functionally equivalent for the real data shape involved, but a logic change, not a presentational one — it was reverted, to keep the sweep's diff honestly presentational-only rather than quietly smuggling in an unrelated behavior change.

## Tokens as code

`tailwind.config.js` and `app.css`'s custom-property blocks are the runtime source of truth. `docs/design/tokens.json` is a hand/generated mirror (nominally regenerated via `scripts/export-tokens.js`) intended for design tooling (Figma plugin) and CI checks against rogue hex literals — as of this session it already includes the chart duotone, score-tier variables, and `badge-neutral`, but treat it as a mirror to double-check against the actual CSS/Tailwind config if the two ever appear to disagree, not as an independent source of truth in its own right.
