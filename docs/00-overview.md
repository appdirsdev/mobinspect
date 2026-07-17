# 00 — Overview & Vision

## What is MobInspect?

**MobInspect** is an open-source mobile application security testing platform. It performs automated **static analysis**, **dynamic analysis**, and **malware/threat-intelligence** scanning on Android (APK / AAB / XAPK), iOS (IPA), and Windows Mobile (APPX) applications.

It is a fork of the well-known [Mobile Security Framework (MobInspect)](https://github.com/MobInspect/mobinspect) project. The fork exists to deliver three things that the upstream codebase does not currently prioritize:

1. **A modern, dynamic user interface** with first-class light & dark themes
2. **Dynamic role-based access control** suitable for multi-tenant security teams
3. **First-class analytics** — trends, throughput, severity distribution, fleet health

## Who is it for?

| Persona | Primary need |
|---------|--------------|
| **Security analyst** | Submit scans, triage findings, write suppressions, export reports |
| **Engineering manager** | Visibility into vulnerability trends across the app portfolio |
| **DevSecOps engineer** | API-driven scans wired into CI/CD pipelines |
| **Compliance/audit** | Read-only access to historical reports, downloadable PDFs |
| **Platform admin** | User and role management, integration configuration |

These personas map directly to the four default roles defined in [03 — RBAC Design](03-rbac-design.md).

## What changes vs. upstream MobInspect?

| Area | Upstream MobInspect | MobInspect |
|------|----------------|------------|
| Brand | MobInspect | MobInspect (full rebrand) |
| UI framework | AdminLTE / Bootstrap 4 | Tailwind CSS v3 + Alpine.js + HTMX + Motion One |
| Themes | Single light theme | Light + dark with system-pref detection |
| Auth | Django auth + SAML2 | Same, plus dynamic RBAC layer |
| Roles | 2 (Maintainer, Viewer) wired only via SAML group mapping | Unlimited dynamic roles, manageable in-product |
| Permissions | 3 hardcoded (`can_scan`, `can_suppress`, `can_delete`) | Granular catalog covering every action |
| Analytics | None | Dashboard with scan trends, severity breakdown, fleet health |
| Page motion | None | Subtle, purposeful (page transitions, card reveals, chart animations) |

## What stays the same?

We are **not** rewriting the analysis engine. The static and dynamic analyzers, the Frida tooling, the malware-domain check, the binary parsers — all the security-critical logic — stays exactly as it is. MobInspect only changes the presentation, access-control, and observability layers around that engine.

## Non-goals

- **Single-page application** — we keep server-rendered Django, with HTMX for partial updates. SPAs add complexity, attack surface, and a JS toolchain we don't need.
- **Multi-tenancy at the data layer** — RBAC restricts what users can do, not what data they see. True per-tenant data isolation is out of scope.
- **Cloud-native rewrite** — MobInspect runs as a self-hosted Django app, like upstream MobInspect. No microservices.
- **Mobile-first UI** — the product is used on workstations by analysts. We make it responsive, but don't optimize for phones.

## Licensing

MobInspect is **GPL-3.0**, inherited from upstream MobInspect. This means:

- Source must remain publicly available
- Modifications must also be GPL-3.0
- Original copyright notices in source files are preserved verbatim
- A new `Copyright (c) <year> MobInspect contributors` line is added alongside, not instead of, the original

See `LICENSE` in the repository root.
