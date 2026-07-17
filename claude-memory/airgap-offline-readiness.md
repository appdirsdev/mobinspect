---
name: airgap-offline-readiness
description: "MobInspect air-gapped/offline behavior — no CVE API, what works vs breaks fully offline, the update_local_db hang trap, and the remediation checklist"
metadata:
  node_type: memory
  type: project
  originSessionId: 1ebacf8a-6b65-4ac7-98db-bfd0d3b1742f
---

Audited MobInspect's external network deps for air-gapped/offline deployment (2026-07-08, 31-agent workflow, spot-checked against code).

**CVE: NO third-party API.** grep-confirmed ZERO CVE/NVD/OSV/vulners/OSS-Index/deps.dev clients. CVSS in reports is computed on-box from static rule metadata (`cvss:` in `android_rules.yaml` etc.) — deterministic, identical online/offline. No live CVE enrichment exists at all (design property, not an air-gap loss).

**Verdict: works air-gapped TODAY** (real static scans of uploaded APK/IPA/APPX complete offline), but not yet air-gap-CLEAN. On a TRUE air-gap every outbound call fails closed: `is_internet_available()` (utils.py:312) returns False in ~10s (5s google + 5s baidu probes), DB updates skip, detection falls back to BUNDLED snapshots.

**Works offline:** CVE/CVSS scoring; core static analysis (manifest/permissions/cert/code/secrets); Exodus tracker detection (bundled `mobinspect/signatures/exodus_trackers` ~572KB); Maltrail domain check (bundled `maltrail-malware-domains.txt` ~10.8MB); VT/Corellium/Windows-VM/iOS-SSH/AppMonsta/SAML all disabled by default (off scan path).

**Degrades gracefully (scan completes, enrichment empty):** Play/App Store metadata (blank); IP geolocation + OFAC tagging (DNS fails; IP2Location BIN is local but no IP resolves); **Firebase exposure SILENTLY DOWNGRADED** — an actually-open DB reports `firebase_db_exists` INFO instead of `firebase_db_open` HIGH; ~10-20s dead probe time per Android scan.

**Breaks/blocks:**
- **🔴 THE HANG TRAP (priority):** `update_local_db()` **utils.py:548, `timeout=3` at :558** then `response.content` — `requests` timeout=3 is BETWEEN-BYTES read, NOT total transfer. Callers: `Trackers.py:51` (Exodus), `MalwareDomainCheck.py:43` (Maltrail), each ~11MB. A TRUE air-gap is safe (probe returns False, download never attempted), BUT a PARTIALLY-connected/throttled/captive link (e.g. prod VM ~200KB/s) makes the probe PASS → download stalls the scan thread for MINUTES, looks deadlocked. This is the root cause of the "scans stall in update_local_db" symptom noted in [[server-deployment]].
- JADX not bundled → offline no Java decompile (Java Source browser blank; smali/apktool scan still completes). Bonus bug: `tools_download.py:98` `opener.open()` has NO timeout → half-open host hangs thread forever.
- Frida binaries can't fetch offline → no dynamic analysis unless pre-staged (fails clean, no hang).
- Download-APK-by-package (APKPure etc.) inherently online → returns failed offline.
- Windows-VM XML-RPC: safe unset (default), but if configured to an unreachable IP, `ServerProxy` (windows.py:244) has no timeout/try-except → hangs or aborts whole .appx scan.

**Geolocation + OFAC offline (analyzed 2026-07-08):** The geo ENGINE is ALREADY fully offline — `mobinspect/signatures/IP2LOCATION-LITE-DB5.IPV6.BIN` bundled + pure-local `IP2Location.get_all(ip)` lookup; OFAC is a hardcoded set in `MalwareDomainCheck.gelocation()` lines 63-75. ONLY offline blocker = `gethostbyname(domain)` at MalwareDomainCheck.py:86 (DNS). CONFIRMED `gethostbyname('8.8.8.8')`→literal IP with NO network, so hardcoded IPs are geo/OFAC-tagged offline TODAY. Cheap wins: literal-IP detection via `ipaddress` (also fixes IPv6, gethostbyname is IPv4-only); replace silent `geolocation=None` (line 102) with an explicit "unresolved-offline" status; render at appsec.py:113-135. Feeding DYNAMIC-captured IPs is the best-but-LARGE win (iOS Corellium pcap is written but NEVER parsed — needs scapy/dpkt; Android capture is httptools/mitmproxy `*.flow.txt` HOSTNAMES not IPs → still needs DNS). Static domains stay unresolvable offline w/o internal DNS or passive-DNS (itself license-encumbered).
**🔴 TWO REAL ISSUES:** (1) **IP2Location LITE license landmine (affects current product, not just air-gap):** `LICENSES/IP2LOCATION LITE DATA.txt` line 11 = "You have no rights to redistribute or resell this products." Shipping the 99MB BIN in a COMMERCIAL defence product likely needs a PAID IP2Location redistribution license or a permissive-geo-DB swap. (2) **OFAC list is factually WRONG:** hardcoded set over-flags non-comprehensively-sanctioned countries (china, vietnam, cyprus, sri lanka, hong kong, haiti) and includes **syria which OFAC TERMINATED June 2025 (EO 14312)**. Comprehensive embargoes = ONLY Cuba/Iran/North Korea + Crimea/Donetsk/Luhansk. Also exact-string match means 'congo'/'crimea'/'donetsk' never fire (IP2Location reports "Congo Democratic Republic"/"Ukraine"/"Russia"). Fix = two-tier refreshable data file (HIGH embargoed-jurisdiction + lower-sev watchlist). OFAC SDN/Consolidated data = US-gov PUBLIC DOMAIN (safe to bundle); AVOID OpenSanctions (CC-BY-NC non-commercial).

**Remediation (~1 day to air-gap-clean):** (1) add `MOBINSPECT_OFFLINE` kill-switch at top of `is_internet_available()` → returns False w/o network (kills probe latency AND prevents update_local_db entry = fixes the hang). (2) Fix `update_local_db` timeout to `(connect,read)` tuple + hard wall-clock cap; same for tools_download opener + Windows ServerProxy. (3) Refresh bundled Exodus/Maltrail DBs from an internal mirror. (4) Pre-stage JADX + Frida (SHA256 pin via `MOBINSPECT_FRIDA_VERIFY=1`). (5) Self-host 2 CDN assets: `fonts.googleapis.com` + `code.ionicframework.com` in `base_layout.html:22-23` + Windows-only Google Fonts branch in PDF templates. (6) Keep opt-in net features unset (all default off). Related: [[server-deployment]], [[local-ai-enhancement]].
