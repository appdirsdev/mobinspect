# 04 — Design System

> The visual + interaction language for MobInspect. Everything below is **enforced by `tailwind.config.js`** — there is no separate stylesheet to drift from this doc.

## Design principles

1. **Information dense, never noisy** — security analysts triage hundreds of findings; whitespace is a tool, not a goal
2. **Severity is the primary signal** — color hierarchy must always serve risk communication first
3. **Dark by default** — analysts work long hours; dark UIs are kinder, and severity colors pop more on dark surfaces
4. **Motion is functional** — every animation must answer "what just happened?" or "what can I do here?" Decoration is forbidden
5. **Keyboard-first** — every action reachable in ≤3 keystrokes; visible focus rings always
6. **Honest empty states** — never show empty tables; explain what would appear and how

## Color tokens

All colors use the **OKLCH color space** in `tailwind.config.js` for perceptually uniform shifts between light and dark themes.

### Brand

```
mobinspect.500   #2563EB  ─ primary CTA (Blue 600)
mobinspect.400   #3B82F6  ─ links, hover lift
mobinspect.600   #1D4ED8  ─ active / pressed
mobinspect.50    #EFF6FF  ─ subtle highlights (light theme)
mobinspect.950   #172554  ─ deepest accent (dark theme)
```

Brand blue chosen because it's the closest to "trust / verified" without being the same as Microsoft, Slack, or every other SaaS. Adjusted to be distinctive against AdminLTE green that MobSF currently uses.

### Severity (semantic, never decorative)

| Token | Light hex | Dark hex | Use |
|-------|-----------|----------|-----|
| `severity.critical` | `#DC2626` | `#F87171` | CVSS 9.0+, malware confirmed |
| `severity.high` | `#EA580C` | `#FB923C` | CVSS 7.0–8.9 |
| `severity.medium` | `#D97706` | `#FBBF24` | CVSS 4.0–6.9 |
| `severity.low` | `#2563EB` | `#60A5FA` | CVSS 0.1–3.9, info findings |
| `severity.passed` | `#16A34A` | `#4ADE80` | check passed, no finding |
| `severity.unknown` | `#64748B` | `#94A3B8` | undetermined, suppressed |

**Rule**: severity colors are **never used for non-severity UI**. A "Save" button is brand blue, never severity blue. A success toast is `system.success`, never `severity.passed`.

### System (interactive states)

| Token | Use |
|-------|-----|
| `system.success` | Toasts, badges, "OK" states |
| `system.warning` | Soft warnings, deprecation notices |
| `system.error` | Validation errors, destructive confirmation |
| `system.info` | Tips, contextual help |

### Surfaces (depth)

5 surface levels, used to convey hierarchy. Each surface has a paired border token.

| Token | Light | Dark | Use |
|-------|-------|------|-----|
| `surface.0` | `#FFFFFF` | `#0B0F1A` | App canvas / page background |
| `surface.1` | `#F8FAFC` | `#111827` | Card / panel background |
| `surface.2` | `#F1F5F9` | `#1F2937` | Nested card, hovered row |
| `surface.3` | `#E2E8F0` | `#374151` | Sidebars, footers, code blocks |
| `surface.4` | `#CBD5E1` | `#4B5563` | Modals, drawers, popovers |
| `border.subtle` | `#E2E8F0` | `#1F2937` | Divider lines |
| `border.default` | `#CBD5E1` | `#374151` | Card borders |
| `border.strong` | `#94A3B8` | `#6B7280` | Form input borders |

### Text

| Token | Light | Dark | Use |
|-------|-------|------|-----|
| `text.primary` | `#0F172A` | `#F1F5F9` | Headings, body |
| `text.secondary` | `#475569` | `#94A3B8` | Labels, metadata |
| `text.tertiary` | `#94A3B8` | `#64748B` | Disabled, placeholder |
| `text.inverse` | `#F8FAFC` | `#0F172A` | On colored backgrounds |
| `text.brand` | `mobinspect.600` | `mobinspect.400` | Links |

### Theme switching

Implemented with Tailwind `darkMode: 'class'`. The `<html>` element gets `data-theme="dark"` (or `light`). A 25-line script at the very top of `<head>` reads `localStorage.theme` *before* paint to prevent flicker. System pref is the default if no choice is stored.

## Typography

### Type stack

```
UI / Body:   "Inter", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif
Code:        "JetBrains Mono", ui-monospace, "Cascadia Code", Menlo, monospace
Headings:    same as UI (single typeface, weight does the differentiation)
```

Self-hosted under `static/mobinspect/fonts/` with `font-display: swap`. WOFF2 only.

### Type scale (1.25 modular)

| Token | Size | Line height | Weight | Use |
|-------|------|-------------|--------|-----|
| `text-display` | 48px / 3rem | 1.1 | 700 | Hero numbers in dashboard |
| `text-h1` | 30px | 1.2 | 600 | Page titles |
| `text-h2` | 24px | 1.25 | 600 | Section headings |
| `text-h3` | 20px | 1.3 | 600 | Card titles |
| `text-h4` | 16px | 1.4 | 600 | Subsections |
| `text-body` | 14px | 1.55 | 400 | Default body |
| `text-small` | 13px | 1.5 | 400 | Metadata, captions |
| `text-tiny` | 12px | 1.4 | 500 | Badges, table headers (uppercase, tracking-wide) |
| `text-mono` | 13px | 1.5 | 400 | Code, hashes, file paths |

## Spacing (4px base)

Tailwind defaults are fine: `0.5 / 1 / 2 / 3 / 4 / 6 / 8 / 12 / 16 / 24` map to `2px / 4px / 8px / 12px / 16px / 24px / 32px / 48px / 64px / 96px`.

**Layout grid**:
- Sidebar: 240px expanded, 64px collapsed
- Topbar: 56px tall
- Main content: max-width 1440px, padded `px-6` desktop, `px-4` tablet
- Card grid gap: 16px (`gap-4`)

## Border radius

| Token | Value | Use |
|-------|-------|-----|
| `rounded-sm` | 4px | Inputs, small badges |
| `rounded-md` | 6px | Buttons |
| `rounded-lg` | 8px | Cards, panels |
| `rounded-xl` | 12px | Modals |
| `rounded-2xl` | 16px | Hero panels (sparingly) |
| `rounded-full` | — | Pills, avatars |

## Shadows / elevation

Five levels, light-on-dark and dark-on-light variants pre-tuned. Avoid blanket `shadow-md`; pick the one that matches the surface level above.

```
elevation-1:   0 1px 2px rgb(0 0 0 / .05)
elevation-2:   0 4px 8px -2px rgb(0 0 0 / .08), 0 2px 4px -2px rgb(0 0 0 / .04)
elevation-3:   0 12px 24px -8px rgb(0 0 0 / .12), 0 4px 8px -4px rgb(0 0 0 / .06)
elevation-4:   0 24px 48px -12px rgb(0 0 0 / .18)
elevation-glow: 0 0 0 4px rgb(37 99 235 / .15)   // focus ring + active brand
```

In dark mode, shadows are subtler; we lean on borders + surface deltas for hierarchy instead.

## Motion

Powered by **Motion One**. Three durations and three easings only.

```js
duration: { fast: 120, base: 200, slow: 320 }   // ms
easing: {
  out:  'cubic-bezier(0.16, 1, 0.3, 1)',     // ease-out-expo, default
  in:   'cubic-bezier(0.7, 0, 0.84, 0)',
  inOut:'cubic-bezier(0.65, 0, 0.35, 1)',
}
```

### Motion patterns

| Pattern | When | Duration / easing |
|---------|------|-------------------|
| **Page transition** | Route change | `200ms / out` — fade + 4px slide-up |
| **Card reveal** | Cards mount above the fold | `320ms / out`, **stagger 50ms** |
| **Hover lift** | Card / button hover | `120ms / out` — `translateY(-1px)` + elevation up |
| **Modal in** | Open dialog | Backdrop fade `200ms`; panel scale 0.95→1 + fade `200ms / out` |
| **Toast in** | Notification | Slide from top-right + fade `200ms / out` |
| **Chart mount** | Chart enters viewport | Bars/lines draw `slow / inOut`, 80ms stagger |
| **Severity pulse** | New critical finding | 2 pulses then stop — *never* infinite |
| **Skeleton shimmer** | Loading | 1.5s linear loop, 8% opacity gradient |

### Always

- Respect `prefers-reduced-motion: reduce` — drop to opacity-only fades, ≤80ms
- Never animate during text entry
- Never animate scroll-jacking; native scroll only

## Components

Every component lives in `mobsf/templates/components/` and is included via `{% include 'components/...' %}`. The component catalog:

### Inputs
- `button.html` — variants: `primary`, `secondary`, `ghost`, `danger`, `link`. Sizes: `sm`, `md`, `lg`. Loading state with inline spinner.
- `input.html`, `textarea.html`, `select.html` — uniform border, focus ring, error state, optional leading icon
- `checkbox.html`, `radio.html`, `toggle.html`
- `file_upload.html` — drag-drop dropzone with progress bar
- `search.html` — global search with kbd hint (`⌘K`)

### Containers
- `card.html` — surface-1 background, optional header / footer / actions
- `panel.html` — full-bleed, no border, used for forms in settings
- `modal.html` — focus-trapped, ESC to close, Alpine-managed
- `drawer.html` — slide-in from right, used for finding details

### Data display
- `table.html` — sortable headers, sticky header on scroll, row hover, bulk-select
- `pagination.html` — page-size selector, jump-to-page, keyboard nav
- `badge.html` — variants for severity, role, status
- `tag.html` — removable, color-coded
- `metric.html` — large number + delta + sparkline
- `chart.html` — wraps Chart.js with theme-aware defaults
- `code.html` — syntax-highlighted block with copy button
- `kbd.html` — keyboard hint pill

### Feedback
- `toast.html` — top-right stack, auto-dismiss with hover-to-pause
- `empty_state.html` — icon + title + body + optional CTA
- `progress.html` — determinate (scan progress) and indeterminate
- `skeleton.html` — for loading rows / cards
- `alert.html` — inline persistent message (info / warning / error / success)

### Navigation
- `sidebar.html` — collapsible, role-aware items, current-route highlight
- `topbar.html` — search, notifications, theme toggle, user menu
- `breadcrumbs.html` — auto-generated from URL conf
- `tabs.html` — keyboard-navigable, animated underline
- `pagination.html`

### Domain-specific
- `severity_badge.html` — color + label + CVSS score
- `score_donut.html` — AppSec score 0–100 with severity-themed ring
- `app_card.html` — icon + name + version + recent scan summary
- `finding_row.html` — used in static analysis report tables

## Iconography

**Lucide** icons rendered as inline SVG via `{% lucide 'shield' size='20' %}` template tag. Stroke width fixed at `1.5`. Color always `currentColor`.

## Accessibility

- **WCAG 2.1 AA** color contrast for all text (verified in CI via `pa11y`)
- Visible focus ring on every interactive element (`focus-visible:ring-2 ring-mobinspect.500`)
- All form inputs have associated `<label>`s
- Modals trap focus and restore on close
- Live regions for toasts (`aria-live="polite"`) and errors (`aria-live="assertive"`)
- Tables use `<th scope="col">` and announce sort state
- Dark/light toggle is keyboard-accessible and announces state

## Tokens as code

`tailwind.config.js` is the runtime source. A mirror at `docs/design/tokens.json` is generated by `scripts/export-tokens.js` and committed — useful for design tools (Figma plugin) and for CI checks (no rogue hex literals).
