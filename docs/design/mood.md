# Visual Mood — MobInspect

A short north-star document for visual decisions. When in doubt, this is the tiebreaker.

## One-line vibe

**"An instrument panel for a SOC analyst."** Dark-first, dense, built to be stared at for hours during a shift — not glanced at once for a demo screenshot.

## Where this comes from

The visual direction isn't open-ended taste — it's modeled on a Behance case study, *"Cyber Security UI/UX Design"* (fictional product **CyberGuard**). The palette hex codes and the Albert Sans display typeface came straight off that reference's own style-guide slides. This was a client-material-pinned brief, not a "go find something cool on Dribbble" exercise, and that changes how we treat it: deviations from the reference need a reason, not a preference.

One thing was **not** inherited from CyberGuard: the brand blue used for navigation, the logo, and every interactive control. That's MobInspect's own identity, decided independently, and it's layered on top of the CyberGuard mirror rather than replacing it. See the policy below — this is the detail most likely to look like an unfinished sweep if you don't know the reasoning, so it's written down twice.

## The three-tier color policy

Every color decision in the product answers to one of these three tiers. Nothing freelances.

1. **Brand blue — "operate the tool."** Sidebar, topbar, logo, nav active-state, the global focus ring, primary buttons, input focus states. This is chrome, not data. It was a deliberate identity call, made separately from the CyberGuard mirror — the "M" monogram predates this rebrand.
2. **Amber/violet duotone — dashboard data only.** Gauge fill, chart series, stat-tile accent bars and glows, non-semantic icon chips. Sourced directly from the reference. It never touches a button, a nav item, or body text — the moment amber shows up on something clickable, it starts competing with brand blue for "what do I click," and the panel stops reading as calm instrumentation.
3. **The dark grain-pill CTA — one hero action per screen.** `.mi-pillbtn`, near-black in both themes (`#17181C` dark / `#1A1A1A` light). CyberGuard's own screens never show two primary CTAs competing for attention on one dashboard, and neither do ours.

Severity color sits outside this tier system entirely, on its own rule: **semantic only, never decoration.** A red badge means a real critical finding, a real failed check, a real risk category — never "this row is exciting." We found this rule being broken in the wild this session (see below), which is exactly why it's written down here in black and white.

## Why the gauge is the signature piece

The 270° radial score meter isn't a chart-library widget dropped in for polish — it's a genuine small engineering choice. No JS charting dependency, no backend trig per value: the pointer's angle comes from composing two CSS `rotate()` transforms, driven by a single Django `{% widthratio %}` tag, and the arc track itself is an SVG `pathLength="100"` + `stroke-dasharray` trick. It's the kind of component that looks simple and isn't, which is the right amount of cleverness for the one element every scan report leads with.

It also carries a rule the rest of the system leans on: color always comes in as `score_color` (a theme-aware CSS variable), never a bare hex. Skip that and the gauge now falls back to gray, not blue — on purpose. It used to silently default to brand blue when no color was passed, which read as a false "everything's fine, this is just chrome" signal on a component whose entire job is telling you severity. Gray-for-unknown is honest; blue-for-unknown was a bug.

## Backgrounds and depth

Dark is the *default* theme app-wide now, not a media-query afterthought — CyberGuard has no light variant, and a SOC dashboard that people live in for a shift should open in the mode it was actually designed for. Light mode still exists and is fully supported, it's just not what greets you.

Surfaces are CSS custom properties (`--surface-0` through `--surface-4`), theme-toggled off `data-theme` on `<html>`, not hardcoded per-component. In dark mode we lean on borders over shadows to convey hierarchy — shadows go visually weak once the background itself is already dark.

Glass is opt-in, not ambient. `.mi-glass` (backdrop blur + saturate) dresses up dashboard-style cards deliberately; it is **not** forced onto the base `.card` class everywhere. Dense tables and forms stay flatly opaque on purpose — translucency under a data table is a readability tax nobody asked to pay.

## Typography

- **Display / headings** — Albert Sans, self-hosted, pulled straight from the reference's type specimen. Tailwind v3's fontSize shorthand config has no `fontFamily` key (confirmed the hard way — it silently drops from the compiled CSS), so this is wired in as an explicit override in `app.css` rather than through `tailwind.config.js` alone.
- **Body / UI** — Inter, unchanged. Kept deliberately over Albert Sans at small sizes: a display face with personality is the wrong choice for a dense data table you're reading at 13px for an hour.
- **Mono / data** — JetBrains Mono, unchanged. Hashes, code, tabular figures.

## Severity is not a decoration budget

Before this session, severity badge classes (`badge-critical`, `badge-passed`, etc.) had leaked into upwards of fifteen templates as a free color palette for things with zero severity meaning — item counts like "75 endpoints," version tags, feature labels. A green `badge-passed` pill next to an unrelated label reads as "this passed a security check" whether or not that's true. `badge-neutral` now exists as the boring, correct default for any count, tag, or label that isn't a real finding or status. If it doesn't have a severity, it doesn't get a severity color.

The score-tier scale itself had the same disease in a different shape: the same red/amber/blue/green ternary was hand-copied into six templates, and a seventh — Analytics — quietly ran a different three-tier scale with no blue/"low" step at all. The same numeric score could render a different color depending which page you were standing on. There's now exactly one threshold scale (`mi_score.py`: <30 critical, <40 medium, <60 low, ≥60 passed), exposed as both CSS variables and template filters. Nobody hand-writes the ternary again.

## Small honesties

- The sidebar persists its expand/collapse state to `localStorage`, because this is a full-page-reload Django app, not an SPA — without persistence, an expanded sidebar would silently re-collapse on every single navigation. That's not a nice-to-have, it's a bug fix.
- Both theme toggles (topbar and sidebar) now share one event (`mi:theme-change`) instead of drifting out of sync with each other.
- Icons are restrained: one per nav item, and inline severity labels lean on color plus an `aria-label`, not an icon doing the same job twice.

## What we didn't build

No candlestick/OHLC chart, no flow/ribbon chart, no compliance-percentage rows, no "Approve / Reject AI action" buttons. Every one of those would either fabricate data MobInspect doesn't have or imply a live-remediation capability that doesn't exist. A good-looking dashboard that lies about what the product can do is worse than a plainer one that doesn't — so we left the gaps visible instead of papering over them with fake polish.
