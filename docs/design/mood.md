# Visual Mood — MobInspect

A short north-star document for visual decisions. When in doubt, this is the tiebreaker.

## One-line vibe

**"A pro's tool, not a dashboard demo."** Quietly confident, dense with information, animated only when it helps you understand what changed.

## Reference points (what we like)

- **Linear** — restrained, fast, every pixel earned, dark mode that's actually dark
- **Sentry** — severity is the visual hierarchy, not nav decoration
- **Datadog (recent)** — chart density without clutter
- **Vercel dashboard** — surface depth used to imply hierarchy
- **Tailscale admin** — calm, trusty, never flashy

## Anti-references (what we avoid)

- Glassmorphism (security users hate translucent UI on important data — readability comes first)
- Neon gradients (signals "crypto", not "professional")
- Emoji-laden empty states (the audience is grown-ups)
- Animated-on-every-hover dashboards (performative, not functional)
- "AI assistant" sidebars (unless we ship one and it earns its space)

## Surfaces

Five surface depths. Most pages use only 2 (canvas + card). Modals jump to surface 4. **Never** stack more than 3 surface levels in a single visible region — it becomes a depth-perception puzzle.

In dark mode we lean on **borders**, not just shadows, to convey hierarchy — shadows become visually weak on dark backgrounds.

## Color discipline

- The **only** colors that should ever convey meaning are the severity tokens. A button that's blue because it's a CTA is fine; a "low severity" finding being green-because-it's-fine is **not** — green means "this passed", not "this is low".
- Brand blue is for navigation, CTAs, links. It must never be confused with the "low severity" blue. Severity blue is `severity.low`, brand blue is `mobinspect.500`. They are deliberately different shades.
- Backgrounds in dark mode trend toward `#0B0F1A` not pure black. Pure black creates harsh borders and reads as "OLED phone", not "pro tool".

## Typography rules

- One typeface for everything except code (Inter)
- One mono for code (JetBrains Mono)
- Numbers use **tabular figures** in tables (`font-feature-settings: 'tnum'`) — alignment matters
- Hashes / file paths use `text-mono` and a subtle background tint so they look "click-to-copy"

## Density

- Default table row height: **40px** (information-dense, scannable)
- Compact mode for long tables: **32px** (toggle in user prefs)
- Card padding: **16px** vertical, **20px** horizontal
- Form field height: **36px**

## Motion philosophy

> If the user can't articulate what an animation taught them, the animation shouldn't exist.

Three motions earn their place:

1. **Reveal**: cards fade-up with 50ms stagger when a page loads. Communicates "the page is ready".
2. **State change**: status pills cross-fade colors over 200ms when a finding is suppressed. Communicates "your action took effect".
3. **Chart entry**: lines/bars draw in over 320ms. Communicates "this is data, not a static image — interact with it".

Everything else is instant or 120ms.

`prefers-reduced-motion` collapses everything to instant + opacity-only fade.

## Iconography

Lucide, stroke 1.5. **One icon per nav item** maximum. Inline severity labels never use icons — color carries the load (with `aria-label` for screen readers).

## Empty states

Always: **icon · title · one-sentence body · optional CTA**. Never just "No data."

Example for an empty Scans table:

```
┌─────────────────────────────────────┐
│           [upload-cloud icon]       │
│        No scans yet                 │
│   Upload an APK, IPA, or AAB to     │
│   get started.                      │
│            [ New Scan → ]           │
└─────────────────────────────────────┘
```

## Loading states

- Skeleton rows for tables (never spinners on full pages)
- Spinner on inline buttons during submit (`aria-busy="true"`)
- Top-of-page progress bar for HTMX boosted nav (~150ms threshold before showing)

## Errors

- Inline beside the field that caused them (form validation)
- Toast for transient failures
- Full page only for 403/404/500 — and those pages are styled, not stack traces (unless `MOBSF_DEBUG=1`)
