---
name: coverage-campaign
description: How to run the full real-execution coverage suite and its ceiling on non-device hosts
metadata: 
  node_type: memory
  type: project
  originSessionId: 85e8d82d-ac91-4200-b3a5-995d0479a70e
---

MobInspect test-coverage campaign (2026-07-04, branch release-2026.7).

**Run the full coverage suite** (default pytest `testpaths` only covers RBAC+Analytics — the real suite is explicit):
```
cd <repo> && source ./.env.postgres && export MOBINSPECT_ADMIN_USERNAME=admin MOBINSPECT_ADMIN_PASSWORD=admin
~/.pyenv/versions/3.13.5/bin/python -m poetry run pytest -q --import-mode=importlib \
  --cov=mobinspect --cov-config=.coveragerc --cov-report=term-missing \
  mobinspect/RBAC/tests mobinspect/Analytics/tests mobinspect/StaticAnalyzer/test_integration.py mobinspect/**/test_cov_*.py
```
- Shell is **zsh**: an unquoted `$VAR` holding space-joined paths does NOT word-split — use the `mobinspect/**/test_cov_*.py` glob, not a variable.
- `--import-mode=importlib` (now pinned in pyproject addopts) is required: two `test_cov_view_source.py` (android + ios) collide otherwise.
- 1072 tests, ~4min (the in-process `test_integration.py` runs real scans of all 13 `test_files/` samples under coverage).

**Coverage reached: 25% → 66.9%** real-execution line coverage (strict, zero mocks). Per-pkg: StaticAnalyzer 82%, MobInspect 83%, RBAC 86%, Analytics 93%, MalwareAnalyzer 69%, DynamicAnalyzer 27%, install 13%.

**Ceiling cause** (why not higher on this Mac): ~3765 uncovered statements are DEVICE-locked (DynamicAnalyzer/Corellium/frida — need a real Android/iOS device); ~365 Windows/install-only; ~178 network (VirusTotal/firebase/maltrail live calls). The identical suite climbs much higher on prod Linux + a device + API keys. True 100% additionally needs mocks for defensive `except`/error branches, which the user declined (strict real-execution). See [[review-fixes-release-2026-7]].

Found+fixed a real bug during the campaign: `shared_func.unzip` `UnboundLocalError` (stop_fallback_extraction initialized inside the try).
