# MobInspect Documentation

This directory contains the design and engineering documentation for the **MobInspect** project — a fork and rebrand of [Mobile Security Framework (MobInspect)](https://github.com/MobInspect/mobinspect) with a modern UI, dynamic RBAC, and analytics.

> MobInspect is licensed under **GPL-3.0**, inheriting from upstream MobInspect.

---

## Reading order

For new contributors, read in this order:

| # | Document | Purpose |
|---|----------|---------|
| 00 | [Overview & Vision](00-overview.md) | What MobInspect is, who it's for, what changes vs. upstream MobInspect |
| 01 | [Architecture](01-architecture.md) | High-level system architecture, Django apps, request lifecycle |
| 02 | [Tech Stack](02-tech-stack.md) | Frameworks, libraries, and the rationale behind each |
| 03 | [RBAC Design](03-rbac-design.md) | Dynamic roles, permission catalog, enforcement model |
| 04 | [Design System](04-design-system.md) | Color tokens, typography, spacing, motion, components |
| 05 | [Information Architecture](05-information-architecture.md) | Sitemap, navigation, page inventory |
| 06 | [Analytics Spec](06-analytics-spec.md) | Dashboard widgets, metrics, data sources |
| 07 | [Rebrand Checklist](07-rebrand-checklist.md) | Every reference that must change from `MobInspect` → `MobInspect` |
| 08 | [Roadmap](08-roadmap.md) | Phased delivery plan with milestones |
| 09 | [Development Setup](09-development-setup.md) | Run locally, build assets, run tests |

## Architecture Decision Records (ADRs)

Short, immutable records of consequential decisions. New ADRs go in `docs/adr/`.

- [0001 — Django Groups as RBAC foundation](adr/0001-django-groups-as-rbac-foundation.md)
- [0002 — Tailwind over Bootstrap](adr/0002-tailwind-over-bootstrap.md)
- [0003 — HTMX + Alpine over SPA](adr/0003-htmx-alpine-over-spa.md)
- [0004 — Server-rendered charts via Chart.js](adr/0004-charts-via-chartjs.md)
- [0005 — Phased rebrand strategy](adr/0005-phased-rebrand-strategy.md)

## Design assets

Mockups, design tokens (JSON), and reference imagery live under `docs/design/`.

## Product state

[`STATE.md`](STATE.md) is a point-in-time, honestly-scored snapshot of what's
verified end-to-end vs. still a known gap — not a design doc, updated per
verification pass rather than kept current line-by-line.

---

## Conventions used in these docs

- **File:line citations** — when a doc references code, it uses `path/to/file.py:42` so you can jump there.
- **Status flags** — sections marked `[NOT YET IMPLEMENTED]` describe target state; `[CURRENT]` describes what's in `master` today.
- **Why over what** — these docs explain *why* decisions were made. The "what" lives in the code.
