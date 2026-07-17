# ADR 0005 — Phased rebrand strategy (rebrand last)

**Status**: Accepted
**Date**: 2026-05-05

## Context

Three concurrent initiatives — rebrand, UI redesign, RBAC — each touch a large portion of the codebase. Done in the wrong order, work gets redone.

Possible orderings:

1. **Rebrand → RBAC → UI**
2. **RBAC → UI → Rebrand** (chosen)
3. **UI → RBAC → Rebrand**
4. **All three simultaneously** (rejected: merge conflicts will eat us)

## Decision

**RBAC first, UI second, rebrand last.**

## Reasoning

### Why RBAC first

- Smallest blast radius. RBAC adds new tables, decorators, and one admin UI surface — visible nowhere else
- Lets the new UI render role-aware navigation from day one (no retrofit)
- Doesn't depend on visual design decisions

### Why UI second

- The UI restyle is the largest and most visible change; doing it after RBAC means we get to design role-aware components correctly the first time
- Pages are migrated in dependency order: foundation → reports → analytics → settings. If we rebranded first, every page touch repeats `s/MobInspect/MobInspect/`

### Why rebrand last

- Find/replace is mechanical; doing it before the UI rewrite means re-doing it (UI templates change extensively in Phase 2)
- The rebrand is a one-day chore, not a multi-day risk; sequencing it last minimizes the window where merge conflicts with upstream are catastrophic
- Ship branches that are usable at every step — even before rebrand, Phase 2 + RBAC means we have a much-improved MobInspect; if the rebrand were first, we'd have a renamed-but-otherwise-unchanged product, which is the worst combination

## Consequences

### Pros
- Each phase is independently mergeable
- We never repeat work
- Public-facing features land continuously

### Cons
- The branding inconsistency (we're calling it MobInspect in docs but the package is still `mobinspect` for weeks) is awkward. Mitigated by clear status flags in templates (`{% comment %}TODO Phase 3 rebrand{% endcomment %}` is *not* used; we just leave the strings as-is and let Phase 3 sweep them).
- Anyone joining mid-stream has to know "we are MobInspect even though the code says MobInspect". Documented in the README before Phase 0 lands.
