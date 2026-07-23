---
name: prod-deployment-2026-07-14
description: "DEPRECATED TOPOLOGY (see update at top) — historical: Prod (192.168.3.65 non-Docker) and AVD (192.168.3.64) servers, systemd services, known AVD hardware instability"
metadata:
  node_type: memory
  type: project
  originSessionId: 67019f0b-e557-4966-8b9c-683562465919
---

**UPDATE 2026-07-21 — topology changed, read this before anything below.**
`.64` is now the ONLY live deployment — it runs the full app via
**Docker Compose** (postgres+ollama+mobinspect+worker+nginx containers, see
[[docker-64-ai-fix]]), not the AVD-only role described further down.
`.65`'s non-Docker install (`mobinspect-web.service` +
`mobinspect-worker.service`, detailed below) was **stopped** on 2026-07-21
per explicit user request ("shutdown the normal server so there's no more
confusion") — `.65` now 502s (its nginx front-end is still up, but the
backing app is fully down). Initially disabled too, but the user asked to
re-enable right after ("dont disable ill manually shutdown the server just
enable the service") — both units are back to **enabled** (will autostart
on boot) while remaining **stopped** right now; the user intends to shut
the server down manually themselves. `.65`'s git checkout, venv, Postgres
data, and nginx config are all left in place (untouched, just not
running) — `systemctl start mobinspect-web mobinspect-worker` would revive
it — but treat `.64`/Docker as the single source of truth for "the
deployed app" going forward. `.65` is still used as a **build server** for
Docker images (more resources for compiling; the resulting image is
transferred to `.64` to run — see [[docker-64-ai-fix]] and the 2026-07-21
session for the build workflow), which is unrelated to and doesn't
require restarting its stopped systemd services.

The rest of this file is the ORIGINAL 2026-07-14 topology snapshot, kept
for historical/rollback reference only — it no longer reflects what's
currently running.

Deployed 2026-07-14. Two LAN servers, both user `mobinspect` (SSH + sudo password shared by the user in-chat — treat as sensitive, don't ever print it or the generated Postgres/secret-key values to output).

**Prod — 192.168.3.65** (Ubuntu 22.04 jammy, VMware VM, 4 core/15GB). Fully working, confirmed via real API scans (android.apk score 36, ios.ipa score 100).
- Repo at `~/MobInspect`, branch `feature/granite-llm-integration`, deployed via `git clone` (public repo, no auth needed) + native venv (NOT poetry — `.venv` created directly with pyenv Python 3.13.5, matching `start.sh`'s Linux convention).
- Deps: JDK 22.0.2 (`~/jdk-22.0.2`, official tarball), JADX via `PYTHONPATH=~/MobInspect .venv/bin/python mobsf/MobSF/tools_download.py ~/.MobInspect` (tools_download.py needs the repo root on PYTHONPATH to resolve `mobsf.MobSF.exceptions` — fails standalone), wkhtmltopdf (needs `libjpeg62-turbo` — NOT in Ubuntu 22.04's default repos as `libjpeg-turbo8`; had to sideload Debian bookworm's `libjpeg62-turbo_2.1.5-2_amd64.deb` via `dpkg -i`, it only drops a `.so.62` file, no conflict with the existing `libjpeg-turbo8`), Node v20.18.1 (official prebuilt tarball, NOT the NodeSource `curl|sudo bash` installer — that pattern is auto-blocked as unverified-root-code-execution on production; use the tarball instead) + `npx tailwindcss@3` to build `dist/app.css`.
- PostgreSQL 14 (Ubuntu default), role/db `mobsf`/`mobsf`.
- `.env.postgres` needs `MOBINSPECT_ALLOWED_HOSTS=<prod-ip>,localhost,127.0.0.1` or Django rejects all requests (DEBUG=0 default only allows 127.0.0.1/localhost). Use `MOBINSPECT_SECRET_KEY` (not the deprecated `MOBSF_SECRET_KEY` — still works via fallback but logs a warning).
- Two systemd services: `mobinspect-web.service` (gunicorn, now `-b 127.0.0.1:8000` — loopback-only, see nginx below) and `mobinspect-worker.service` (qcluster), both `EnvironmentFile=.env.postgres` + explicit `JAVA_HOME`/`PATH`. Both `Restart=on-failure`.
- Admin login: username `admin`, password set by explicit user request to the same value as the box's SSH/sudo password (their choice, flagged the credential-reuse tradeoff once, they proceeded). Set via Django shell (`set_password`) + `Group.objects.get_or_create(name='Administrator')` — **being a Django superuser alone is NOT enough**, the RBAC layer (`request.mi_permissions`) checks group membership, not `is_superuser`. Any admin account created here needs to be added to the `Administrator` group too, or every RBAC-gated view 403s despite superuser status.
- `MOBINSPECT_ALLOWED_HOSTS` / `MOBSF_ANALYZER_IDENTIFIER=192.168.3.64:5555` set in `.env.postgres` — the AVD pointer is currently DEAD (see below), dynamic analysis will fail until repointed at a new AVD host.
- **nginx reverse proxy (2026-07-14)**: installed and fronting the app on port 80 (`server_name 192.168.3.65 _`, `client_max_body_size 500M`, `proxy_read/send_timeout 3600s` to match gunicorn's own timeout, standard `X-Forwarded-*` headers). Config at `/etc/nginx/sites-available/mobinspect`, symlinked into `sites-enabled`, default site removed. gunicorn was moved from `0.0.0.0:8000` to `127.0.0.1:8000` as part of this — nginx is now the sole external entry point; port 8000 is no longer reachable from outside the box. `nginx` + `mobinspect-web` + `mobinspect-worker` + `postgresql` are all `systemctl enable`d (auto-start on boot). Static assets (still served by whitenoise inside gunicorn, nginx just proxies everything) confirmed working through the proxy. Full login→upload→scan→report cycle verified live through `http://192.168.3.65/` (port 80, no `:8000`).

**AVD — 192.168.3.64** (Ubuntu 24.04, VMware VM, nested KVM via VT-x passthrough, 4 core/15GB). **STOPPED per user decision — do not restart without new instruction.** User is moving AVD hosting to different hardware.
- Had a pre-existing Android 11 (API 30) AVD (`android11_avd`) already set up before this session, matching the project's own `MobInspect_API30` convention (`start.sh:88`).
- Systemd units created: `mobinspect-avd.service` (emulator, `-no-window -writable-system -no-snapshot`) and `mobinspect-adb-forward.service` (socat forwarding external `:5555` → the emulator's loopback adb port, for cross-machine reachability since the emulator's own adb port only ever binds to `127.0.0.1`).
- **socat gotcha**: `TCP-LISTEN:5555` with no bind= defaults to the wildcard address, which collides with the emulator's own `127.0.0.1:5555`/`[::1]:5555` binds (EADDRINUSE) — Linux won't let a wildcard and a specific-address listener share a port even across processes. Fix: bind socat explicitly to the host's LAN IP (`bind=192.168.3.64`), not the wildcard.
- **Root cause of instability**: MobInspect's dynamic-analysis `mobsfy` step requires `/system` writable (`environment.py: system_check()` does `adb shell touch /system/test`). First-time verity-disable + overlayfs remount NEEDS one `adb reboot` to take effect (standard Android behavior, not a MobInspect bug) — but on THIS VM, that reboot (and subsequent sustained emulator operation) reliably triggers a **KVM hardware fault**: `KVM: entry failed, hardware error 0x7` / `kvm_arch_handle_exit: hardware error happened in KVM, aborting`. This is a nested-virtualization (VMware→KVM→QEMU) stability issue at the hypervisor level, not fixable from inside the guest. Proved the underlying capability works once (full boot → root → verity-disable → overlayfs remount all succeeded) before the fault hit on the next reboot; systemd's `Restart=on-failure` then crash-looped it 25+ times before I stopped both services.
- If a new AVD host is stood up: reuse this same systemd-unit pattern (avd + adb-forward), but pick hardware with either bare-metal KVM or a nested-virt-tested hypervisor config, and budget for the mandatory first-boot verity-disable+reboot cycle before /system is writable.

See [[local-ai-enhancement]], [[ai-integration-implemented]] for the AI-pipeline side, which is fully deployed and independent of the AVD issue.
