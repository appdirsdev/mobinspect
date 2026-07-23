---
name: design-system-conventions
description: "MobInspect UI design-system rules — reticle-M logo, warm/blue two-zone hero convention, the rgb(var(--token)) gotcha, role color palette"
metadata: 
  node_type: memory
  type: project
  originSessionId: 67019f0b-e557-4966-8b9c-683562465919
---

Design conventions established while elevating the MobInspect UI (feature/granite-llm-integration). Committed across 5 scoped commits and pushed to `github/feature/granite-llm-integration` on 2026-07-14 (not yet merged to mobinspect/main).

**Logo mark, v2 (2026-07-14, current)** — `components/logo_mark.html` is now a medallion monogram: a bold geometric **M** on a solid circular seal (brand blue gradient `#3C82F6`→`#1D4ED8`), single confident white stroke, no ornamentation. Same mark in `favicon.svg`/`logo.svg`. Replaced the "reticle-M" (v1, below) per an explicit user request to redesign "creative... simple classical and modern... forget about application nature" — i.e. deliberately NOT scan/security-themed imagery this time.

**Logo mark, v1 (retired)** — the "reticle-M": blue app tile + bold white M framed by camera-style viewfinder brackets + an amber scan-dot at the M's vertex. Superseded by v2 above; kept here only for history if v2 is ever reconsidered.

**Two-zone hero convention** — pages open with a `.mi-hero` ambient card (glow + faint grid). TWO signatures, don't flatten them:
- **Warm scan-flow zone** (home, dynamic, recent_scans): amber `#FE4A23` + violet `#8D5CFC` glow, plus a light page-level `.mi-ambient` bloom behind all content.
- **Blue admin/config zone** (rbac roles, api_keys, audit_log, adb integrations): brand-blue `rgba(37,99,235,…)` glow, hero card only (no page-level `.mi-ambient`).

**rgb(var()) token gotcha** — CSS custom tokens like `--border-subtle` are RGB TRIPLES (`226 232 240`), NOT full colors. They MUST be used as `rgb(var(--border-subtle))`. Bare `var(--border-subtle)` compiles but renders nothing (silent fail) — this had hidden the hero grid texture on roles_list.html + audit_log.html. Always wrap token vars in `rgb(...)`.

**Role color palette** — the four seeded roles draw from the brand palette, NOT severity colors: Administrator = violet `#8D5CFC`, API User = amber `#FE4A23`, Security Analyst = blue `#2563EB`, Viewer = slate `#64748B`. Migration `RBAC/0013_recolor_default_roles.py` remaps the old Administrator red `#DC2626` / API-User green `#16A34A` (which collided with finding-severity semantics) on existing DBs; seed `0003` updated for fresh installs. Rule: role/category accents never use severity red/green.

Multi-line Django comments MUST be `{% comment %}…{% endcomment %}` — `{# #}` is single-line only and leaks as visible text (recurring bug). See [[fullsweep-redesign-tests]], [[ai-integration-implemented]].
