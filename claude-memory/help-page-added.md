---
name: help-page-added
description: "In-app Help/user-guide page added to the sidebar — covers the product end to end, never mentions the underlying open-source base"
metadata:
  node_type: memory
  type: project
  originSessionId: 67019f0b-e557-4966-8b9c-683562465919
---

Added 2026-07-14 on `feature/granite-llm-integration` (committed + pushed). New route `GET /help/` (name `help_center`), view `mobsf.MobSF.views.home.help_center`, template `mobsf/templates/general/help.html`. Linked from the sidebar (`components/sidebar.html`, bottom utility group, reuses `components/sidebar_item.html` for active-state consistency with the rest of the nav).

Covers: getting started, running a scan, reading a report (per-section explanations), the security score (deterministic, always available), the AI Dashboard (4-stage enrichment, AI risk score is a server-side aggregate not model-generated, gated to completed scans, works fully offline), Integrations (model + device connections), dynamic analysis, roles & access (default role table), API access, and a 6-item FAQ accordion (`<details>`-based, no JS framework needed).

**Hard constraint enforced and worth remembering for any future user-facing copy**: the user explicitly required zero mentions anywhere in the Help content of the underlying open-source project this fork is built on — the product is referred to only as "MobInspect" / "the platform." Verified via grep before shipping.

Same visual language as report pages (`.mi-report-hero`, `.mi-quicknav` sticky section nav, `card mi-glass` panels) — no new design system introduced. See [[design-system-conventions]].
