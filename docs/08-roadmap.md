# 08 — Roadmap

A phased delivery plan. Each phase is independently shippable; the product is usable after every phase. Estimates assume one full-time developer; parallelism cuts wall-clock proportionally.

## Phase 0 — Foundation (≈0.5 day)

**Goal**: scaffolding for everything that follows. Nothing user-visible changes.

- [ ] Create local git branch `mobinspect`
- [ ] Add Tailwind standalone CLI binary under `tools/tailwindcss` (committed for reproducibility)
- [ ] `tailwind.config.js` with the design tokens from [04 — Design System](04-design-system.md)
- [ ] Source CSS at `mobsf/static/mobinspect/css/app.css` with `@layer base`, `@layer components`, `@layer utilities`
- [ ] Build script `scripts/tailwind-build.sh` (one-shot) and `scripts/tailwind-watch.sh` (dev)
- [ ] Vendor Alpine, HTMX, Motion One, Chart.js, Lucide into `mobsf/static/mobinspect/vendor/` with `LICENSES.md`
- [ ] Add `mobsf/MobSF/templatetags/lucide.py` for inline-SVG icon rendering
- [ ] Add `mobsf/MobSF/templatetags/theme.py` for the no-flicker theme bootstrap script
- [ ] Smoke commit: empty page rendered with new base layout, theme toggle works

**Deliverable**: a `/playground/` route only visible in DEBUG mode that demos Tailwind, light/dark, and the icon set.

## Phase 1 — Dynamic RBAC (≈2 days)

**Goal**: ship the RBAC system without changing visible behavior — then progressively gate views in Phase 2.

### 1.1 Models & migrations (≈0.5 day)
- [ ] New Django app `mobinspect.RBAC` (initially placed alongside `mobsf/`, renamed in Phase 3)
- [ ] Models: `Permission`, `Role`, `RoleAssignment`, `AuditEvent`, `ApiKey`
- [ ] Migration 0001: create tables
- [ ] Migration 0002: seed permission catalog (33 permissions per [03 — RBAC](03-rbac-design.md))
- [ ] Migration 0003: seed default roles (Administrator, Security Analyst, Viewer, API User)
- [ ] Migration 0004: backfill existing users; existing `Maintainer`/`Viewer` Django Groups → linked to new system roles by name

### 1.2 Enforcement (≈0.5 day)
- [ ] `mobinspect/RBAC/decorators.py` — `@require_permission`, `@require_role`, `@require_any_permission`
- [ ] `mobinspect/RBAC/middleware.py` — populate `request.role_set`, `request.permissions_set`
- [ ] `mobinspect/RBAC/api.py` — API auth helper that checks key → user → permissions
- [ ] `mobinspect/RBAC/templatetags/rbac.py` — `{% can %}`, `{% has_role %}`
- [ ] `mobinspect/RBAC/audit.py` — record events on grant / revoke / denial
- [ ] Update existing 3 permission decorators to delegate to the new system without changing call sites

### 1.3 Admin UI (≈1 day)
- [ ] `Settings → Users` — list, create, edit, delete; assign roles
- [ ] `Settings → Roles & permissions` — list system + custom roles, color-coded
- [ ] Role editor — name, description, color, icon picker (Lucide), permission assignment matrix
- [ ] Permission catalog browser — grouped by category, filterable
- [ ] `Settings → My API keys` — create / name / revoke; show key once at creation
- [ ] `Settings → Audit log` — table with filters

**Deliverable**: a working RBAC system with default roles seeded, manageable in-product, no breakage of existing behavior.

## Phase 2 — UI redesign (≈3 days)

Each sub-phase is one or two commits, independently mergeable.

### 2.1 Foundation pages (≈0.5 day)
- [ ] New `base/app.html` (sidebar + topbar layout, role-aware nav, breadcrumbs, toast region)
- [ ] Sign-in page redesign
- [ ] 403 / 404 / 500 pages
- [ ] Empty / loading / error component states

### 2.2 Scans & reports (≈1 day)
- [ ] Scans list (was `general/recent.html`)
- [ ] Static analysis report (Android, iOS, Windows binary + source)
- [ ] AppSec scorecard
- [ ] Compare view
- [ ] Source tree browser

### 2.3 Dynamic analysis (≈0.5 day)
- [ ] Dynamic analyzer device picker
- [ ] Android dynamic UI (analyzer, report, frida_logs, live_api, logcat)
- [ ] iOS dynamic UI (Corellium and device variants)

### 2.4 Analytics (≈0.5 day)
- [ ] Dashboard
- [ ] Trends, severity, top CWEs, coverage, throughput pages
- [ ] Daily rollup `django-q2` job
- [ ] Backfill management command

### 2.5 Settings (≈0.5 day)
- [ ] Profile, security (was change_password), theme, notifications
- [ ] Integrations (VirusTotal, SAML, proxy, webhooks placeholder)
- [ ] About page
- [ ] API docs page (restyle existing)

**Deliverable**: every page in the product uses the new design system. No more AdminLTE references in templates.

## Phase 3 — Rebrand (≈0.5 day)

Per [07 — Rebrand Checklist](07-rebrand-checklist.md), four passes:
- [ ] Pass 1: Python package `mobsf` → `mobinspect`
- [ ] Pass 2: Env vars + filesystem paths + deprecation shim
- [ ] Pass 3: User-visible strings + brand assets
- [ ] Pass 4: Build, Docker, CI, README

**Deliverable**: `mobinspect serve` boots; `MOBINSPECT_HOME=/tmp/mi mobinspect` works end-to-end.

## Phase 4 — Hardening & polish (≈1 day, optional)

- [ ] Pa11y / axe-core CI for accessibility regressions
- [ ] Lighthouse CI budget for the dashboard
- [ ] Component snapshot tests (Storybook-equivalent for Django templates)
- [ ] Webhook integration (Slack on critical findings, email digests)
- [ ] Documentation site generated from `docs/`

## Total estimate

| Phase | Effort | Cumulative |
|-------|--------|-----------|
| 0 | 0.5d | 0.5d |
| 1 | 2.0d | 2.5d |
| 2 | 3.0d | 5.5d |
| 3 | 0.5d | 6.0d |
| 4 (optional) | 1.0d | 7.0d |

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Template restyle introduces regressions in scan reports | Golden-file tests for the JSON payloads underpinning each report; visual regression on key pages |
| RBAC migration breaks existing SAML role mapping | Keep `Maintainer` / `Viewer` Django Groups; map them to new system roles by name |
| Tailwind CLI version drift | Pin the binary; commit it to `tools/`; CI verifies sha256 |
| Phase 3 rebrand breaks deployments | Two-release deprecation shim for env vars; document migration in CHANGELOG |
| GPL compliance slipups during rebrand | Lint rule: every source file must have an unchanged MobSF copyright line |

## Out of scope (this roadmap)

- Mobile-first UI
- Multi-tenancy at the data layer
- SaaS-style billing / subscription
- Replacing the analysis engine
- New analyzers (Flutter, React Native specific tooling)
- Web-based decompiler / Frida script editor
