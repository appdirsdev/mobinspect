---
name: local-ai-enhancement
description: "Feasibility + model choice for adding local CPU AI to enhance MobInspect scan results (defence, air-gapped, non-Chinese, permissive license) — researched + live-tested 2026-07-08"
metadata:
  node_type: memory
  type: project
  originSessionId: 1ebacf8a-6b65-4ac7-98db-bfd0d3b1742f
---

Explored adding a **local, CPU-only, open-source LLM/embedding layer** to MobInspect to enhance scan output, for **defence-forces buyers** (air-gapped, no cloud AI, license must be clean + non-Chinese). Two deep-research workflows + a live on-device test (2026-07-08).

**Model shortlist (all non-Chinese, permissive, CPU-viable):**
- **IBM Granite 4.0 Micro 3B / 4.1-8B** — Apache-2.0, NO acceptable-use policy, IBM-signed weights, GGUF via Ollama/llama.cpp. TOP PICK. (Granite 4.0 "Small" 32B/9B does NOT fit RAM budget.)
- **Microsoft Phi-4-mini 3.8B** — MIT. **SmolLM3-3B** — Apache-2.0, 64-128K ctx.
- **nomic-embed-text-v1.5** — Apache-2.0 embeddings, 137M/~274MB, negligible CPU; use for dedup/similarity/clustering (deterministic, no hallucination, runs even on the weak 2vCPU/3.3GB prod VM).
- **DISQUALIFIED: Meta Llama** — AUP verbatim bans "Military, warfare... espionage" + ITAR; Nov-2024 carve-out is Five-Eyes only, not India. **Gemma** = second-tier (mutable AUP). All Chinese models excluded per requirement.

**Live test (this 8GB M1, `granite4:micro` Q4, pure CPU `-ngl 0` via llama.cpp) against REAL `android_rules.yaml` data — all 4 task types worked:**
- (C) Secrets classification: **6/6 correct**, clean JSON — production-ready at 3B.
- (D) Version-delta verdict: decisive + correct — production-ready at 3B.
- (A) Finding explain/remediate: correct, named the exact method + fix (had CWE fed in).
- (B) Exec fielding verdict: correct top-3 + decisive reject.
- **Perf: ~7.5 tok/s generation, ~37 tok/s prompt (single process, contention-free).** Two model procs on 8GB → swap → 0.3 tok/s (artifact). Fine for **async django-q enrichment**, too slow to block a page. 8GB M1 fits ONE 3B model only.

**Honest limits (adversarial benchmark research):**
- Instruction-following is Granite's one strong verified skill (IFEval 81-87, 3B≈8B). That's why C/D work at 3B.
- **Free-form generation collapses below 8B** (ArenaHard 3B 37.8 vs 8B 68.98). Use **8B for A/B** on real/long reports; 3B only for C/D + short inputs. H-Tiny is 1B-active MoE = weakest, avoid.
- **CRITICAL: never let the model recall CWE/OWASP** — general 4-8B models get 37-50% of CVE→CWE mappings WRONG. Feed the metadata from the rule files (already present: cvss/cwe/owasp-mobile/masvs) and let the model only phrase. Ground everything (RAG-style).
- Zero cybersec benchmark exists for Granite; IBM's own CyberPal 2.0 uses Qwen3 bases. **Must run an in-house eval on a MobInspect corpus before trusting.**
- 3B effective context ~16-32K real (RULER 58 @128K) → dynamic-analysis "summarize 1000s of Frida calls" needs structural pre-aggregation, keep prompts ≤32K.

**Product features (9 verified feasible against code, ranked impact/effort) — see [[ai-product-features]] if written; key ones:** per-finding remediation (Granite, `_finding_group.html` raw `<pre>` today; htmx vendored but unused), exec summary on scorecard/PDF, secrets triage (Phi-4-mini; fixes a real bug — single secret never reported, `appsec.py:179`), embeddings dedup across sections (nomic, runs on prod VM), and **the honest prerequisite: CVSS-weighted ranking needs NO model** — `appsec.py` already has cvss/cwe/owasp/masvs per code-finding and throws it away when flattening; carry it through + sort by CVSS first.

**Server sizing for 8B, ~5 users (researched + verified 2026-07-08):** CPU LLM inference is **memory-bandwidth-bound, not core-bound** — gen tok/s = mem_bandwidth / model_bytes. Cores past ~8 only speed prefill; buy DDR5 CHANNELS not cores. Measured 8B Q4 gen: Ryzen 9 7950X (2-ch ~90GB/s) ~11 tok/s; Xeon 8480+ (8-ch) ~45 tok/s; **EPYC Genoa 9554 (12-ch ~460GB/s) ~50 tok/s**; old Xeon ~7. "5 users" ≠ 5 streams: async django-q queue, only 1-2 llama-server `--parallel` slots needed (adding slots on CPU splits bandwidth, doesn't add aggregate throughput). **RECOMMENDED SPEC: EPYC Genoa 8-16 cores / 12-ch DDR5-4800 / 32 GB RAM / Granite-4 8B Q4_K_M / --parallel 2 → ~1.5 min async enrichment per scan** (~1.9K out + ~7K in tokens/scan). RAM breakdown co-located: 8B Q4 ~4.9GB + 3B Q4 ~2GB + nomic ~0.3GB + KV 2 slots ~1.5GB + OS ~2GB + Django/PG/qcluster ~4GB ≈ 15GB working set (32GB = headroom; capacity never the constraint). 5-scan simultaneous burst worst case: ~6-8 min (recommended), ~20 min (8-core dual-channel min tier). Q5 for quality = +15-25% latency. Small-KV RAM win only holds for Granite-4's hybrid Mamba (dense 3.x 8B ~2x KV). GPU would be 10-30x faster but off-table for air-gap.

**Runtime gotcha:** Homebrew `ollama` 0.30.6 on this Mac is BROKEN — `llama-server` runner binary missing, `ollama run` → 500. Ran the model via **`brew install llama.cpp` + `llama-cli -m <gguf-blob>`** instead (the ollama-pulled blob at `~/.ollama/models/blobs/sha256-6c0268…` IS a valid GGUF). For the real integration, use the official Ollama.app, not the brew formula. Deploy split: embeddings on prod VM; LLM generation on a 16GB on-prem box (8B needs ~5GB). Config via a `MOBINSPECT_AI_URL` env flag following existing `MOBSF_/MOBINSPECT_` conventions. Related: [[release-2026-7]], [[server-deployment]].
