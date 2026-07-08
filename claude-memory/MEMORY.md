# MobInspect — memory index

- [release-2026-7](release-2026-7.md) — active work branch: review fixes, admin/admin cred convention, creds-in-history security debt, local dev env
- [coverage-campaign](coverage-campaign.md) — how to run the full real-execution coverage suite; reached 66.9%, ceiling is device/Windows/network-locked
- [local-ai-enhancement](local-ai-enhancement.md) — local CPU AI to enhance scans (defence/air-gap): Granite 4.x + nomic-embed shortlist, live-tested on M1 (works, ~7.5 tok/s), honest limits, 9 product features, llama.cpp runtime gotcha, 8B server sizing for 5 users
- [airgap-offline-readiness](airgap-offline-readiness.md) — offline/air-gap map: NO CVE API (local CVSS), what works vs breaks fully offline, the update_local_db timeout=3 between-bytes HANG trap on throttled links, ~1-day remediation checklist
- [ai-integration-implemented](ai-integration-implemented.md) — Granite LLM enrichment IMPLEMENTED + tested on feature/granite-llm-integration: separate admin-only AI Dashboard page, background daemon thread (scans serialized workers=1), full guardrails, scan pipeline untouched, uncommitted
