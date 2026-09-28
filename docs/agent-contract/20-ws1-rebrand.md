# W1 — Rebrand completion

Goal: no upstream identity (MobSF / Mobile Security Framework / its author's handles and hosts) in
any shipped file, and none of the damage the earlier blind find-and-replace left behind. Exactly one
attribution survives (D1), in `LICENSE.md` + `NOTICE`.

Branch: `ws/1-rebrand`, split into four commits — identifiers, links, `.github`, docs. Gates on exit:
G-code, G-rebrand (must exit 0), G-e2e.

What the earlier pass got wrong, so it is not repeated: it rewrote the *upstream* name inside
identifiers, URLs and prose, producing `mobinspecty` (the "prepare the device" feature), links to a
`github.com/MobInspect/…` organisation that does not exist, a Slack invite with a swapped workspace
name, upstream security advisories relabelled as ours, and sentences like "Rebrand Checklist
(MobInspect → MobInspect)". Every task below reverses one class of that.

## 1.1 `mobinspecty` family → `prepare_device` — M

| Where | Now | After |
|---|---|---|
| `mobinspect/DynamicAnalyzer/views/android/environment.py:635` | `is_mobinspectyied()` | `is_device_prepared()` |
| `environment.py:657` | `mobinspecty_init()` | `prepare_device_init()` |
| `environment.py:58, 810` | call sites | updated |
| `mobinspect/DynamicAnalyzer/views/android/operations.py:69, 88` | `def mobinspecty` | `def prepare_device` |
| `mobinspect/DynamicAnalyzer/views/android/dynamic_analyzer.py:232-237` | calls | updated |
| `mobinspect/MobInspect/urls.py:336` | `^mobinspecty/$ name='mobinspecty'` | `^prepare_device/$ name='prepare_device'` |
| `urls.py:137` | `^api/v1/android/mobinspecty$` | add `^api/v1/android/prepare_device$`; keep the old path routed to the same view, responding with a `Deprecation: true` header and one `logger.warning` per process (D8, removed next release) |
| `mobinspect/MobInspect/views/api/api_android_dynamic_analysis.py:104-114` | `api_mobinspecty`, docstring | `api_prepare_device` |
| `mobinspect/templates/dynamic_analysis/android/dynamic_analysis.html:79,80,89,129,334,527,569,593,615` | `#mi-mobinspecty`, `#mi-mobinspecty-btn`, `{% url "mobinspecty" %}` | `#mi-prepare-device`, `#mi-prepare-device-btn`, `{% url "prepare_device" %}` |
| `mobinspect/templates/general/apidocs.html:378,2056,2060,2125` | API path + anchor | new path; old path listed as deprecated |
| tests `mobinspect/MobInspect/views/api/test_cov_api_android_dynamic_analysis.py:175-176,263-266,434`, `tests_e2e/ui/specs/test_general_dynamic.py:285` | old ids/paths | new + one test asserting the alias still answers |
| `deploy/systemd/mobinspect-avd.service:48`, `deploy/scripts/avd-provision.sh:4`, `deploy/RUNBOOK.md:454` | comments | updated |

Acceptance: `curl` both API paths with the same body → identical JSON; `tests_e2e` dynamic spec passes; `git grep -i mobinspecty` empty.

## 1.2 AVD name — S

`scripts/start-all.sh:88` and `scripts/run-mobinspect.sh:16` default to `MobInspect_API30`; every other
place (`README.md:52`, `deploy/RUNBOOK.md:89,115,233-235`, `mobinspect-avd.service`) says `MobInspect_AVD`.
Use `MobInspect_AVD` everywhere. Acceptance: one name in `git grep -n 'MobInspect_A'`.

## 1.3 The 98 MSTG links — S

`mobinspect/StaticAnalyzer/views/android/rules/android_rules.yaml` (41), `…/ios/rules/swift_rules.yaml` (35),
`…/ios/rules/objective_c_rules.yaml` (22) reference `https://github.com/MobInspect/owasp-mstg/blob/master/Document/…`.
These render in every scan report. Rewrite mechanically to `https://github.com/OWASP/owasp-mastg/blob/master/Document/…`
(the archived paths still resolve; `mas.owasp.org` restructured its anchors, so a curated remap is a
later, separate task). Then:

```
git grep -ho 'https://github.com/OWASP/owasp-mastg[^ "]*' mobinspect/StaticAnalyzer | sort -u | \
  while read u; do printf '%s ' "$(curl -s -o /dev/null -w '%{http_code}' -I "$u")"; echo "$u"; done | grep -v '^\(200\|301\|302\) '
```

Acceptance: the loop prints nothing; `git grep -c 'github.com/MobInspect'` is 0.

## 1.4 Other dead URLs — S

- `mobinspect/StaticAnalyzer/views/common/binary/macho.py:89` — delete the comment line.
- `mobinspect/templates/general/dynamic.html:214` and `manage.py:16` — `mobinspect.github.io/docs` → the in-app `/help/` page.
- `mobinspect/install/windows/readme.md:9` — raw URL → `raw.githubusercontent.com/appdirsdev/mobinspect/…`.

## 1.5 `.github/` community files — S

- `SECURITY.md` — the ~25 links are upstream GHSA advisories, commits and issues relabelled as ours. Replace the file with a short disclosure policy (contact, response window, supported versions, no bounty). Nothing from the old file is kept.
- `CONTRIBUTING.md:18-19,72,106,110`, `SUPPORT.md:1`, `ISSUE_TEMPLATE/bug_report.md:11,29,50` — remove the Slack invite (it is upstream's token with a swapped workspace name) and the Stack Overflow search link; point at GitHub issues.
- `PULL_REQUEST_TEMPLATE.md:14` — drop the badge.
- `workflows/auto-comment.yml:19,28` — rewrite the messages.
- Delete `workflows/python-publish.yml` (no PyPI publishing) and `FUNDING.yml`.

## 1.6 Submodule — S

`.gitmodules` points `mobinspect/StaticAnalyzer/test_files` at a repository that does not exist; the
directory is empty (`git submodule status` shows `-`). The real fixtures are the tracked root
`test_files/`, already used by `mobinspect/StaticAnalyzer/test_integration.py:23`.

`git rm --cached mobinspect/StaticAnalyzer/test_files && git rm .gitmodules`; then
`mobinspect/StaticAnalyzer/tests.py:27,183` → the root `test_files/` path. Acceptance: `git submodule status`
prints nothing; the `/tests/` self-test (after W3.8 puts it behind auth) finds its fixtures.

## 1.7 Docs and comments de-garble — M

Rewrite `docs/07-rebrand-checklist.md` as **"Rebrand record"**: what the upstream project was, what
was renamed, what this workstream reversed, why each allowlist rule exists. It is the one document
allowed to name the upstream project in full and is allowlisted for that reason.

Fix the sentences that now say "MobInspect → MobInspect" or "upstream MobInspect" in:
`docs/README.md:3,5,15,22`, `docs/00-overview.md:7,25,27,46,51`, `docs/01-architecture.md:62`,
`docs/03-rbac-design.md:13`, `docs/05-information-architecture.md:130`, `docs/08-roadmap.md:90,123`,
`docs/09-development-setup.md:7,49`, `docs/adr/0001…:15`, `docs/adr/0002…:8`, `docs/adr/0005…` (throughout),
`README.md:124`, `mobinspect/MobInspect/init.py:28-31`, `mobinspect/MobInspect/test_cov_init.py:84,298`,
`mobinspect/templates/general/home.html:433`, `mobinspect/RBAC/tests/conftest.py:45`,
`mobinspect/MobInspect/tools_download.py:89,95`, `scripts/dependencies.sh:36-37`, `deploy/RUNBOOK.md:68`.
Also drop the `asgi.py` entries at `.coveragerc:137,158` (no such file).

Acceptance: a human reads each changed paragraph and it makes sense; G-rebrand green.

## 1.8 Attribution (D1) — S

Add `NOTICE` at the repo root:

> MobInspect is a derivative work of Mobile Security Framework (MobSF), Copyright Ajin Abraham and contributors, licensed under GPL-3.0. Modifications Copyright Appdirs.

Keep the contributor roster in `LICENSE.md` (lines 17-60) unchanged; both files are allowlisted.
Acceptance: `scripts/check-rebrand.sh` lists no residual line in either file.

## 1.9 Session notes (D2) — S

`project-memory/` and `claude-memory/` stay tracked and allowlisted (the user's 2026-09-28 decision).
Keep them synced from `~/.claude/projects/<repo>/memory/` whenever memory changes; never edit the
repo copies by hand. They are excluded from the image by `.dockerignore`.

## 1.10 Not renamed (recorded) — —

`mobinspect/MobInspect/` (the Django project module) keeps its mixed case. It owns no database
tables, but `mobinspect.MobInspect.settings/urls/wsgi` is referenced in `manage.py:10`,
`mobinspect/__main__.py:9`, `mobinspect/MobInspect/wsgi.py:20`, `pyproject.toml:84`, three
`tests_e2e` conftest/spec files, both Dockerfiles, every entrypoint and run script, and the systemd
units. Renaming it is churn with deploy risk and no user-visible value.

`opensecurity.clipdump` in `environment.py:347,482` is the Android package id compiled into the bundled
`ClipDump.apk`; it changes only when someone rebuilds and re-signs that APK. Allowlisted.

## 1.11 Operator task (not code) — S

Rotate the Gitea password embedded in the `origin` remote URL and run
`git remote set-url origin http://192.168.3.244:3000/Appdirs/Mobins.git` with a credential helper.
Acceptance: `git remote -v` shows no secret.
