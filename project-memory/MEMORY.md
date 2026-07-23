# MobInspect — memory index

- [release-2026-7](release-2026-7.md) — active work branch: review fixes, admin/admin cred convention, creds-in-history security debt, local dev env
- [coverage-campaign](coverage-campaign.md) — how to run the full real-execution coverage suite; reached 66.9%, ceiling is device/Windows/network-locked
- [local-ai-enhancement](local-ai-enhancement.md) — local CPU AI to enhance scans (defence/air-gap): Granite 4.x + nomic-embed shortlist, live-tested on M1 (works, ~7.5 tok/s), honest limits, 9 product features, llama.cpp runtime gotcha, 8B server sizing for 5 users
- [airgap-offline-readiness](airgap-offline-readiness.md) — offline/air-gap map: NO CVE API (local CVSS), what works vs breaks fully offline, the update_local_db timeout=3 between-bytes HANG trap on throttled links, ~1-day remediation checklist
- [ai-integration-implemented](ai-integration-implemented.md) — Granite LLM enrichment: 4-stage pipeline (report/secrets/risk/anomalies), deterministic AI risk score, dashboard access gating, comprehensive test pass (1 bug found+fixed). COMMITTED + PUSHED 2026-07-14
- [fullsweep-redesign-tests](fullsweep-redesign-tests.md) — IN-FLIGHT full sweep: creative redesign of all 45 templates (workflow + baselines), then Playwright UI + backend coverage; infra + resume steps + honest-coverage ceiling
- [design-system-conventions](design-system-conventions.md) — logo v2 (medallion-M, 2026-07-14), warm/blue two-zone hero convention, the rgb(var(--token)) silent-fail gotcha, brand role-color palette, {% comment %} rule
- [report-pages-jquery-regression](report-pages-jquery-regression.md) — FIXED 2026-07-14: missing jQuery include + DataTables empty-state crash + duplicate table ids on report pages
- [help-page-added](help-page-added.md) — in-app Help/user-guide page added 2026-07-14, sidebar-linked, zero mentions of the underlying open-source base
- [prod-deployment-2026-07-14](prod-deployment-2026-07-14.md) — UPDATED 2026-07-21: .65's non-Docker systemd services (mobinspect-web/-worker) deliberately STOPPED, .64 Docker is now the sole live deployment; rest of file is historical 2026-07-14 topology (nested-KVM AVD fault etc.)
- [docker-64-ai-fix](docker-64-ai-fix.md) — .64 Docker stack full e2e (2026-07-20/22): AI "not connected" fix, nginx stale-IP 502, worker false-unhealthy, and the Dockerfile-baked Tailwind build fix for the missing-CSS-on-fresh-clone bug
- [tests-e2e-suite](tests-e2e-suite.md) — tests_e2e/ Playwright+API suite: conventions, taxonomy markers, 3-layer RBAC denial shapes; the 3 bugs it found all RESOLVED 2026-07-22 (/find/ 500 + blank-email FIXED; legacy-permission "bug" was a create_roles test-env artifact)
- [repo-reorg-2026-07-21](repo-reorg-2026-07-21.md) — root scripts folded into scripts/ (start.sh→start-all.sh), STATE.md→docs/, the self-locating-script cd-dirname gotcha + how it was verified safe
- [verify-dont-trust-agent-reports](verify-dont-trust-agent-reports.md) — feedback: independently re-verify subagent-reported numbers/claims before relaying as fact; always prove "nothing broken" after a reorg, don't assume it
