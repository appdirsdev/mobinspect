# 02 — Tech Stack

## TL;DR

| Layer | Choice | Why |
|-------|--------|-----|
| Backend | **Django ≥3.1.5** (currently 5.2.7) | Inherited; mature, batteries-included |
| Web server | **Gunicorn** (Unix) / **Waitress** (Windows) | Inherited |
| DB | **SQLite** (default) or **PostgreSQL** | Inherited |
| Async tasks | **django-q2 1.7.4** | Inherited |
| Auth | Django auth + **python3-saml** | Inherited; we layer dynamic RBAC on top |
| **CSS** | **Tailwind CSS v3** (standalone CLI binary, no Node runtime) | Utility-first, no design churn, ships nothing to client we don't use |
| **JS — interactivity** | **Alpine.js 3** (~15 KB) | Server-rendered first; sprinkle reactivity where needed |
| **JS — partial updates** | **HTMX 1.9** (~14 KB) | Form submissions, table reloads, modal swaps without full page loads |
| **JS — motion** | **Motion One** (~5 KB) | Web Animations API wrapper; modern, declarative |
| **Charts** | **Chart.js 4** (~70 KB) + **chartjs-plugin-zoom** | Mature, no React dep, theming hooks |
| **Icons** | **Lucide** (inline SVG via Django template tag) | 1000+ icons, tree-shakable, consistent stroke style |
| **Fonts** | **Inter** (UI) · **JetBrains Mono** (code) | Self-hosted under `static/mobinspect/fonts/` |

## Why these choices for a security application

### Tailwind over Bootstrap (current)
- **Smaller payload** — atomic classes mean we ship only what we use; current AdminLTE/Bootstrap is ~250 KB CSS, our target is <40 KB
- **No "framework look"** — every Bootstrap site looks the same; security tools should feel purposeful, not generic
- **Dark mode is first-class** via `dark:` variants — no parallel stylesheet to maintain
- **Design tokens in code** — `tailwind.config.js` is the single source of truth, mirrored in `docs/design/tokens.json`

See [ADR 0002](adr/0002-tailwind-over-bootstrap.md).

### HTMX + Alpine over React/Vue
- **No build pipeline shipped to production** — Tailwind CLI runs at *build* time; Alpine and HTMX are vendored single-file scripts
- **No bundler attack surface** — supply-chain risk for a security product is paramount; we want to audit ~30 JS files, not 30,000
- **Server-rendered = SEO + accessibility for free** and we keep CSRF protection working without custom token plumbing
- **Django stays Django** — no API/UI split, fewer moving parts

See [ADR 0003](adr/0003-htmx-alpine-over-spa.md).

### Motion One over GSAP / Framer
- GSAP has commercial-license edge cases; Framer Motion is React-only
- Motion One uses the **native Web Animations API** — accelerated, accessible (`prefers-reduced-motion` honored), tiny

### Chart.js over D3
- D3 is a graphics library; Chart.js is a charting library — we want charts, not bespoke viz
- Tree-shakable, theme-able via Tailwind CSS variables, mature

### Lucide over Font Awesome / Material Icons
- MIT licensed, no attribution required
- Inline SVG = themeable via `currentColor`, no font-rendering quirks, no separate request

## Build pipeline

```
┌──────────────────┐   tailwindcli   ┌──────────────────────┐
│ tailwind.config  │─────────────────►│ static/mobinspect/   │
│ +  app.css        │   --watch       │   css/app.css        │
└──────────────────┘                  └──────────────────────┘
        ▲
        │ scans for class names in...
        │
mobsf/templates/**/*.html
mobsf/**/*.py
```

- **Dev**: `./scripts/tailwind-watch.sh` — runs the standalone CLI in watch mode, ~5 ms rebuilds
- **CI**: `./scripts/tailwind-build.sh` — minified, purged, hashed output
- **No Node.js required at runtime or for production builds** — we use the standalone Tailwind CLI binary distributed by the Tailwind team, downloaded once and committed to `tools/tailwindcss-<version>` (or fetched in CI)

## Vendored / third-party JS

All shipped JS lives under `mobsf/static/mobinspect/vendor/` with a `LICENSES.md` next to it. Subresource integrity hashes are computed at build time. We **do not** load any JS from third-party CDNs at runtime — same supply-chain rationale as above.

| Library | Version | License | SHA256 |
|---------|---------|---------|--------|
| Alpine.js | 3.x | MIT | (filled at vendor time) |
| HTMX | 1.9.x | BSD-2 | |
| Motion One | 10.x | MIT | |
| Chart.js | 4.x | MIT | |
| Lucide | latest | ISC | |

## Python additions

The rebrand & RBAC work add no new Python dependencies. The analytics dashboard uses:
- Django ORM aggregates (`Count`, `Avg`, `TruncDay`, `TruncWeek`) — no new lib needed
- `django.db.models.functions.Now` for time-series buckets

If we later add scheduled report generation, we'll consider `django-celery-beat`, but for now `django-q2` (already installed) handles cron-style schedules.

## What we considered and rejected

| Considered | Rejected because |
|------------|------------------|
| Bootstrap 5 | Less control over the visual identity; Tailwind is the modern equivalent |
| Tailwind via npm | Adds Node.js to the build, increases supply-chain surface |
| Stimulus | Smaller community than Alpine; less interop with HTMX out of the box |
| Vue / React island | Build complexity; SSR vs hydration headaches; not justified for our interactivity needs |
| ApexCharts | Heavier, theming is harder, more opinionated visually |
| django-htmx | Just a couple of decorators we don't strictly need; we'll write a 30-line context processor instead |
| django-allauth | We have SAML2 + Django auth already; allauth is overkill |
| django-guardian (object-level perms) | Out of scope — RBAC is action-level, not row-level |
