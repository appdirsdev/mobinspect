# Third-party licence risks

Bundled data and tools whose licence terms need an owner before the product is sold or
redistributed. None of these block a contract gate; D15 tracks the first one.

| Item | Where | Size | Concern | Options |
|---|---|---|---|---|
| IP2Location LITE DB5 IPv6 | `mobinspect/signatures/IP2LOCATION-LITE-DB5.IPV6.BIN` | 95 MB | `LICENSES/IP2LOCATION LITE DATA.txt` line 11: no right to redistribute or resell. Shipping it inside a commercial image is redistribution. | Buy the redistribution licence; or swap to a permissively licensed GeoIP database; or download at install time under the customer's own acceptance. |
| maltrail malware domains | `mobinspect/signatures/maltrail-malware-domains.txt` | 10 MB | Upstream feed licence (MIT for the project; the feed aggregates third-party lists). Confirm redistribution terms per source list. | Keep with attribution in `LICENSES/`; refresh from an internal mirror for air-gapped sites. |
| Exodus tracker signatures | `mobinspect/signatures/exodus_trackers` | 560 KB | Exodus Privacy data is CC-BY-SA 4.0 — share-alike on the data. | Keep with attribution; do not merge into proprietary data files. |
| apktool, baksmali, bundletool, JADX, vd2svg, apksigner | `mobinspect/StaticAnalyzer/tools/`, JADX at build time | ~60 MB + JADX | Apache-2.0 / BSD; notices must ship. | `LICENSES/` already carries them; verify each version's NOTICE file is present. |
| wkhtmltopdf, OpenJDK 22, Ollama, Granite models | image layers | large | LGPL-3 (wkhtmltopdf), GPL-2+CE (OpenJDK), MIT (Ollama), Apache-2.0 (Granite). All compatible with redistribution; notices must ship. | Add a `THIRD-PARTY-NOTICES.md` generated in W3 listing every binary in the image with its licence. |
| ClipDump.apk, XposedInstaller | `mobinspect/DynamicAnalyzer/tools/onDevice/` | 3 MB | Upstream-built helper APKs (GPL-3 as part of the derivative work). | Rebuild and re-sign under the new identity when D14 is picked up. |
| OFAC country list | `MalwareDomainCheck.py` | — | Hard-coded and factually stale (includes jurisdictions no longer under comprehensive sanctions); OFAC source data is public domain. | Replace with a refreshable data file (tracked in W2 backlog, not a licence issue but recorded here so it is not lost). |
