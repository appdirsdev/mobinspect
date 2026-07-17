# ADR 0002 — Tailwind CSS v3 over Bootstrap / AdminLTE

**Status**: Accepted
**Date**: 2026-05-05

## Context

Upstream MobInspect uses AdminLTE 3, a Bootstrap 4 admin template. The full UI redesign needs a CSS strategy. Candidates:

1. **Stay on Bootstrap 5 + custom theme**
2. **Tailwind CSS v3** (utility-first)
3. **Tailwind CSS v4** (CSS-first config)
4. **Custom plain CSS / SASS**

## Decision

Use **Tailwind CSS v3** with the standalone CLI (no Node.js runtime, no `package.json` in production).

## Why not v4?

Tailwind v4 dropped late 2024 and uses a different config approach. v3 is more battle-tested; v4 still has rough edges around Django-template scanning and the standalone binary on some platforms. We re-evaluate after v4 has 12 months of public release.

## Why not Bootstrap 5?

- AdminLTE has a strong "Bootstrap admin look" that's hard to escape without rewriting most components anyway
- Theming via Bootstrap variables produces a different *colour palette*, but the layout and component shapes stay
- Dark-mode support requires either a parallel stylesheet or extensive `data-bs-theme` overrides — Tailwind's `dark:` variants are vastly more ergonomic
- Bootstrap CSS is ~250 KB; a Tailwind build for our ~50 templates is targeting <40 KB after PurgeCSS

## Why not custom CSS?

- Loses the design-token discipline we want (`tailwind.config.js` is the single source of truth)
- 50 templates of bespoke CSS = naming bikeshedding + drift
- Tailwind's purge step ensures we never ship classes we don't reference

## Standalone CLI

We use Tailwind's official standalone binary (`tailwindcss-<platform>`) committed to `tools/`. This means:

- **No Node.js in production** — Python-only deployment
- **No npm supply chain** — one binary, sha256-pinned
- **No version drift** — the binary is the version

For CI we re-download against the pinned sha256.

## Consequences

### Pros
- Smallest payload, design-token discipline, dark mode for free
- No Node runtime dependency
- Fast iteration (utility classes inline in templates)
- Easy to find unused / dead styles (PurgeCSS shouts about them)

### Cons
- Verbose markup — `class="flex items-center gap-3 px-4 py-2 ..."` instead of `class="btn btn-primary"`. Mitigated by `@apply` for repeated patterns and reusable Django includes for components.
- Engineers new to Tailwind have a learning curve. Mitigated by [04 — Design System](../04-design-system.md).
- AdminLTE-specific JS (sidebar, menu, etc.) gets retired — we rewrite with Alpine.

## Migration

Templates aren't migrated wholesale. Phase 2 of the roadmap walks page-by-page. Until each page is migrated, both stylesheets coexist (`/static/adminlte/...` and `/static/mobinspect/...`). After Phase 2 completes, AdminLTE assets are removed in a single cleanup commit.
