# ADR 0003 — HTMX + Alpine.js over a Single-Page Application

**Status**: Accepted
**Date**: 2026-05-05

## Context

The redesign requires "dynamic motion UI" with light/dark theming. The canonical 2026 way to do that in many shops is React/Vue/Svelte + an API. We considered:

1. **Server-rendered Django + HTMX + Alpine.js** (current direction)
2. **Django REST + React/Vue SPA**
3. **Django + a thin React-island for hot spots**
4. **Inertia.js**

## Decision

Stay **server-rendered** with **HTMX** for partial updates and **Alpine.js** for in-page interactivity.

## Reasoning (security-product specific)

- **Supply chain**: an SPA pulls hundreds of npm packages. For a security tool, every package is a potential compromise vector. HTMX (~14 KB single file) and Alpine (~15 KB single file) are auditable in an afternoon.
- **CSRF**: Django CSRF protection works without ceremony for server-rendered forms. SPAs need explicit CSRF token plumbing or move to bearer-token auth (which has its own issues).
- **No build step shipped to prod**: Tailwind builds CSS once at deploy time. No webpack/vite, no source maps, no hydration mismatches.
- **Accessibility for free**: progressive enhancement is the default; SPAs require explicit ARIA work for parity.
- **Operational simplicity**: one process serves HTML; no separate API server, no CORS, no separate auth context.

## Where motion lives

- **Tailwind animations** for trivial transitions (hover, focus)
- **Motion One** (~5 KB, Web Animations API wrapper) for orchestrated motion (page-load reveals, modal in/out, chart entry)
- **Alpine `x-transition`** for show/hide

No Framer Motion (React-only), no GSAP (license edge cases for commercial use).

## Where HTMX is used

- Form submissions that update a single panel (suppress finding, edit role)
- Tables: filter / sort / paginate without full reload
- Drawers and modals fetched on demand
- Long-poll for scan progress (replaces the JS polling code currently in `general/tasks.html`)

## Consequences

### Pros
- Tiny client payload, fast TTI, no hydration
- Django-template-driven; one mental model
- Zero build complexity in production
- Easy for security-minded teams to audit

### Cons
- Highly interactive views (e.g., the source-tree code browser) need more careful Alpine wiring than they would with React. Mitigated by treating these as isolated components.
- No code-sharing of view models between client and server. We don't need it.
- New contributors used to React land have a learning curve. Mitigated by docs.

## Rejected alternatives

### Inertia.js
Bridges Django + a frontend framework with shared routing. But we'd still need Vue/React, and the JS bundle problem stays. Not worth it.

### Thin React island
The "use React only where necessary" approach. Reasonable, but every island still requires a build pipeline, and once you have one you tend to grow it. We avoid the on-ramp entirely.
