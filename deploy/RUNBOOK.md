# Deployment runbook — production bootstrap, gotchas, recovery

This complements the Gitea wiki's `Installation` and `Troubleshooting` pages with the **load-bearing steps that aren't obvious from the code alone**. Read this once before doing a fresh deploy.

## Current production target

- `192.168.2.118` (Ubuntu 22.04 LTS, 6 vCPU, 15 GB RAM, 77 GB disk, KVM exposed)
- Three systemd units: `mobinspect.service`, `mobinspect-worker.service`, `mobinspect-avd.service`
- Drop-in: `/etc/systemd/system/mobinspect.service.d/avd.conf`
- Web on `0.0.0.0:8001` (terminate TLS upstream — see *Operations → TLS termination*)

## Production readiness checklist

After the C1–C7 / H1–H17 audit pass, the following are **on by default** in this repo. Verify each box before declaring a fresh deploy "live".

| Item | Where it lives | How to verify |
|------|----------------|---------------|
| `ALLOWED_HOSTS` driven by `MOBINSPECT_ALLOWED_HOSTS` (no `*` default) | `mobsf/MobSF/settings.py:191` | `curl -H 'Host: evil.example' http://<host>:8001/` returns 400 |
| Secure session/CSRF cookies + HSTS + `X-Frame-Options=DENY` + CSP, gated on `MOBINSPECT_BEHIND_TLS=1` | `mobsf/MobSF/settings.py:200` | `curl -sI https://<host>/ \| grep -iE 'strict-transport\|x-frame\|set-cookie.*secure'` |
| `MIDDLEWARE` tuple includes `SecurityMiddleware`, `CommonMiddleware`, `XFrameOptionsMiddleware`, ratelimit middleware | `mobsf/MobSF/settings.py` MIDDLEWARE | `poetry run python manage.py check --deploy` returns 0 warnings on the headers checks |
| SQLite **WAL + `busy_timeout=20000`** | `mobsf/MobSF/settings.py` DATABASES OPTIONS | `sqlite3 ~/.MobInspect/db.sqlite3 'PRAGMA journal_mode;'` → `wal` |
| `MOBINSPECT_ASYNC_ANALYSIS=1` (also the settings.py default) on the web drop-in + gunicorn `--workers=2 --max-requests=200 --timeout=180` | `deploy/systemd/mobinspect.service.d/avd.conf`, `mobinspect.service` `ExecStart` | `systemctl show mobinspect.service -p Environment \| grep ASYNC` |
| `/healthz` + `/readyz` reachable, unauthenticated | `mobsf/MobSF/views/healthz.py` | `curl -s http://127.0.0.1:8001/healthz \| jq .status` returns `ok`/`degraded`/`failed` |
| Hourly SQLite backups + 14-day retention | `mobinspect-backup.{service,timer}` | `systemctl list-timers mobinspect-backup.timer` + `ls /var/backups/mobinspect/` |
| Audit signals on (login / logout / api auth fail / admin user.* / RBAC changes) | `mobsf/RBAC/signals.py`, `mobsf/RBAC/audit.py` | `poetry run python manage.py shell -c "from mobsf.RBAC.models import AuditEvent; print(AuditEvent.objects.count())"` after a few logins |
| AuditEvent **hash chain** + DB-level immutability triggers | `mobsf/RBAC/models.py`, migrations 0006/0007 | `poetry run python manage.py audit_verify` returns 0 |
| systemd hardening: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, `MemoryMax`, `TimeoutStopSec=600` on all three units | `deploy/systemd/*.service` | `systemd-analyze security mobinspect.service` exposure score ≤ 5.0 |
| Default `mobsf/mobsf` superuser **removed** — initial admin via `manage.py bootstrap_admin` | `mobsf/MobSF/management/commands/bootstrap_admin.py` | `User.objects.filter(username='mobsf').exists() == False` after bootstrap |
| Frida server **SHA256-verified** before push to device; spawn retry bounded | `mobsf/DynamicAnalyzer/views/common/frida/server_update.py`, `frida_core.py` | journal: `frida-server hash matches`; no infinite `Failed to spawn` loop |
| `wkhtmltopdf` installed (PDF report export) | system package; optional `MOBINSPECT_WKHTMLTOPDF_BINARY` override | `which wkhtmltopdf`; clicking *PDF* on a report returns a PDF, not a 503 |

If any row above doesn't pass, **don't expose the host outside the LAN** until it does.

## Fresh-deploy steps that the README doesn't fully cover

### 0. System (apt) dependencies

Beyond the Python deps installed by `poetry install`, the host needs a handful of
system packages. The README covers most; the one that bites a fresh deploy is
**`wkhtmltopdf`** — without it the *PDF* export button returns an opaque error.

```bash
sudo apt-get update
sudo apt-get install -y \
  wkhtmltopdf \
  openjdk-17-jdk-headless   # JADX / apktool runtime (if not already present)
```

`wkhtmltopdf` is what `pdfkit` shells out to when you click *PDF* on a report
(`mobsf/StaticAnalyzer/views/common/pdf.py`). If it is **not** on `PATH`, the
report view now returns a clear **HTTP 503**
(`PDF export requires wkhtmltopdf - install it ...`) instead of a 500 — but the
fix is still to install the binary.

If the binary lives somewhere off `PATH` (custom build, non-standard prefix),
point MobInspect at it explicitly via the drop-in:

```ini
[Service]
Environment=MOBINSPECT_WKHTMLTOPDF_BINARY=/opt/wkhtmltox/bin/wkhtmltopdf
```

This is read into `settings.WKHTMLTOPDF_BINARY` and passed to
`pdfkit.configuration(wkhtmltopdf=...)`. Leave it unset to rely on `PATH`.

### 1. StaticAnalyzer migrations (was the #1 deploy gotcha)

Upstream MobSF gitignores `mobsf/StaticAnalyzer/migrations`. We **un-gitignore** it in this fork and ship `0001_initial.py` in the repo. If you ever see:

```
sqlite3.OperationalError: no such table: StaticAnalyzer_recentscansdb
```

it means the migrations directory was somehow missed. Regenerate:

```bash
mkdir -p mobsf/StaticAnalyzer/migrations
touch mobsf/StaticAnalyzer/migrations/__init__.py
poetry run python manage.py makemigrations StaticAnalyzer
poetry run python manage.py migrate StaticAnalyzer --noinput
```

### 2. AVD: API level must be ≤ 30

`mobsf/DynamicAnalyzer/views/android/environment.py:40` has `ANDROID_API_SUPPORTED = 30`. Newer images are rejected by `system_check()`.

```bash
sdkmanager 'system-images;android-30;google_apis;x86_64'
echo "no" | avdmanager create avd -n MobInspect_AVD \
  -k 'system-images;android-30;google_apis;x86_64' --device 'pixel_4'
```

### 3. AVD one-time root + disable-verity

After first boot of a fresh AVD, you must disable Android Verified Boot once so MobInspect can remount `/system` rw at scan time. The systemd unit launches the emulator with `-writable-system` so this is *possible*; the steps below make it *take effect*:

```bash
adb root            # → "restarting adbd as root"
sleep 3
adb disable-verity  # → "Successfully disabled verity"
adb reboot
# wait for boot_completed=1
adb root
adb remount         # → "remount succeeded"  (one-time verification)
```

The verity-off state persists across reboots because the emulator's userdata partition is persistent (no `-read-only` flag).

### 4. AVD service flags — what they mean and why each matters

The `mobinspect-avd.service` `ExecStart` flags:

| Flag | Why |
|------|-----|
| `@MobInspect_AVD` | name of the AVD to launch |
| `-no-window` | headless |
| `-no-audio` | no PulseAudio dep |
| `-no-boot-anim` | faster boot |
| `-no-snapshot` | always cold-boot, no stale state from saved snapshot |
| `-gpu swiftshader_indirect` | software GPU (no GL drivers needed on the host) |
| `-writable-system` | wraps system + vbmeta in a CoW overlay so `adb disable-verity` can write |

**Do not add `-read-only`** — it discards changes on shutdown, including the disable-verity state and any installed APKs.

### 5. systemd drop-in for the web service

`/etc/systemd/system/mobinspect.service.d/avd.conf`:

```ini
[Service]
Environment=ANALYZER_IDENTIFIER=emulator-5554
Environment=MOBINSPECT_ADB_BINARY=/home/ubuntu/android-sdk/platform-tools/adb
Environment=MOBINSPECT_ASYNC_ANALYSIS=1
```

`MOBINSPECT_ADB_BINARY` (or the legacy `MOBSF_ADB_BINARY`) is read by `mobsf.MobSF.settings`. Without it, `get_adb()` falls into a `find_process_by('adb')` proc-scan that hits PermissionError on other-uid `/proc/*/exe` reads, returns `None`, and the "Prepare runtime" UI shows:

```
argument should be a str or an os.PathLike object where __fspath__ returns a str, not 'NoneType'
```

`MOBINSPECT_ASYNC_ANALYSIS=1` (the settings.py default — this line is belt-and-braces) makes the web service hand scans off to the django-q2 broker instead of running them inside the gunicorn worker. **This is the production default** — without it, a single static scan can pin a gunicorn worker for minutes and the UI stops responding to anyone else. The `mobinspect-worker.service` unit already sets the same flag; both sides must agree, otherwise tasks queue up but nothing drains them. The worker is therefore **required** for any non-trivial scan (APK static analysis, dynamic analysis, source-zip scans). If you stop the worker, the UI will queue tasks and show "Scanning…" indefinitely.

### 6. Resource limits and systemd sandboxing

All three units ship with explicit resource ceilings and sandboxing flags so a single runaway scan or wedged emulator can't take the host down or stomp outside its own working tree. Numbers are tuned for the **6 vCPU / 15 GB RAM** production box — if you migrate, recalculate proportionally.

| Unit | Memory | Tasks / FDs | Sandbox |
|------|--------|-------------|---------|
| `mobinspect.service` (gunicorn) | `MemoryHigh=6G`, `MemoryMax=8G` | `TasksMax=4096`, `LimitNOFILE=16384` | `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, `ProtectHome=read-only` + `ReadWritePaths=/home/ubuntu/MobInspect /home/ubuntu/.MobInspect` |
| `mobinspect-worker.service` (django-q2) | `MemoryHigh=3G`, `MemoryMax=4G` | `TasksMax=2048` | same sandbox as the web unit |
| `mobinspect-avd.service` (emulator) | `MemoryHigh=4G`, `MemoryMax=6G` | (inherits defaults) | `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict` + `ReadWritePaths=/home/ubuntu/.android /home/ubuntu/.MobInspect`, `ProtectHome=read-only`, `ProtectKernelTunables`, `ProtectControlGroups`, `DeviceAllow=/dev/kvm rw`, `DeviceAllow=/dev/net/tun rw` |

Sum of `MemoryMax` is `8 + 4 + 6 = 18 GB` — that's deliberately over-subscribed on a 15 GB box. The values are *ceilings*, not reservations; in practice the worker sits near idle (~200 MB) when no scan is running and the AVD sits around 1.5 GB. `MemoryHigh` is the soft throttle (kernel starts reclaiming aggressively); `MemoryMax` is the hard kill line.

The web service also overrides two stop-related knobs:

- `KillSignal=SIGTERM` — gunicorn's graceful-shutdown handler keys off `SIGTERM`; sending `SIGINT` (the systemd default for some setups) skips the handler.
- `TimeoutStopSec=600` (was `30`) — long enough for a stuck synchronous scan to finish writing its sqlite row before systemd `SIGKILL`s it. If a stop genuinely hangs longer than 10 min, `systemctl kill -s KILL mobinspect.service`.

`ReadWritePaths` is the **one knob to update** if you ever move the install root or data dir. The defaults assume `/home/ubuntu/MobInspect` (checkout) and `/home/ubuntu/.MobInspect` (data, sqlite, uploads, scan output). For the AVD unit it's `/home/ubuntu/.android` (AVD state + locks) plus `/home/ubuntu/.MobInspect`.

If you need to relax the sandbox while debugging a "permission denied" that *might* be `ProtectSystem`/`ProtectHome` related, drop into the unit and temporarily flip `ProtectSystem=full` to `ProtectSystem=off` and `ProtectHome=read-only` to `ProtectHome=off`, then `daemon-reload` + restart. Revert as soon as you've confirmed the root cause — these flags exist because the gunicorn workers run as `ubuntu` and would otherwise have full write access to the user's home.

### 7. The admin user

`seed_rbac` creates roles only, not users. Bootstrap the initial admin via the dedicated management command — it is **idempotent** (re-runs are a no-op once any superuser exists) and refuses to ever recreate the upstream `mobsf/mobsf` account.

```bash
# Preferred: supply the password out-of-band (systemd EnvironmentFile,
# docker secret, ansible vault, etc.) so it never lands in shell history.
sudo -u mobinspect \
  MOBINSPECT_ADMIN_USERNAME=superadmin \
  MOBINSPECT_ADMIN_PASSWORD='<a-strong-12+char-password>' \
  poetry run python manage.py bootstrap_admin
```

If you omit `MOBINSPECT_ADMIN_PASSWORD`:

- On a TTY the command prompts (with confirmation) and never echoes.
- On a non-TTY (the systemd `ExecStartPre` path) it generates a 24-char `secrets.token_urlsafe` and writes it to `~/.MobInspect/initial-admin-password.txt` (mode `0600`). The full path is logged at INFO — read it once, then delete the file.

Then bind the new admin to the Administrator role:

```python
# poetry run python manage.py shell
from django.contrib.auth.models import User
from mobsf.RBAC.models import Role, RoleAssignment
u = User.objects.get(username='superadmin')
RoleAssignment.objects.get_or_create(user=u, role=Role.objects.get(name='Administrator'))
```

Password floor is **12 characters** (`AUTH_PASSWORD_VALIDATORS` in `settings.py`). Pick something a password manager generated.

> **If you used the legacy bootstrap** (any pre-C7 deploy that ran `createsuperuser --noinput` with `DJANGO_SUPERUSER_PASSWORD=mobsf`, or a RUNBOOK snippet that set `changeme123`): rotate **immediately**. The old `mobsf` user and any `changeme123` password were considered compromised the moment they shipped. Easiest path:
>
> ```bash
> # Delete the legacy user, then bootstrap a fresh one with a strong password.
> poetry run python manage.py shell -c \
>   "from django.contrib.auth.models import User; User.objects.filter(username__in=['mobsf','superadmin']).delete()"
> MOBINSPECT_ADMIN_USERNAME=superadmin \
> MOBINSPECT_ADMIN_PASSWORD='<new-strong-password>' \
>   poetry run python manage.py bootstrap_admin
> ```

## Recovery: AVD wedged in `offline` state

```bash
adb kill-server && adb start-server
sudo systemctl restart mobinspect-avd.service
# wait ~90s for boot_completed=1
```

If it stays offline after restart, the emulator's pid is alive but Android is stuck (kernel panic / OOM in the guest). Full unit restart + a fresh boot usually fixes it. Persistent failure means recreate the AVD (`avdmanager delete avd -n MobInspect_AVD` + recreate).

## Recovery: AVD crash-loop on stale lock files

Symptom: `mobinspect-avd.service` never reaches `boot_completed`, `systemctl status` shows a climbing `NRestarts=`, and the journal repeats a FATAL line like:

```
emulator: ERROR: Running multiple emulators with the same AVD is an experimental
feature. Please use -read-only ...
```

Cause: an unclean shutdown (OOM kill, host reboot, `kill -9`, or a `Restart=on-failure` that fired mid-boot) left lock/scratch files in `~/.android/avd/MobInspect_AVD.avd/` (`*.lock`, `*.lock.lock`, `snapshot.lock*`, `*.tmp*`). qemu sees them on the next start, refuses to attach to the AVD, and exits FATAL. Since we deliberately do **not** run with `-read-only` (see §4 — it would discard disable-verity + installed APKs), the service cannot self-heal: every restart hits the same locks.

This is now handled automatically: `mobinspect-avd.service` ships two `ExecStartPre=-` lines that (1) `pkill` any orphaned `qemu-system-x86_64` bound to this AVD and (2) `rm -f` the stale lock + scratch files before each start. Both are `-`-prefixed so a clean start (nothing to kill / no locks) is a no-op and never blocks boot.

Manual cleanup (if you're on an older unit or the AVD path moved):

```bash
sudo systemctl stop mobinspect-avd.service
pkill -9 -f 'qemu-system-x86_64.*MobInspect_AVD' || true
rm -f /home/ubuntu/.android/avd/MobInspect_AVD.avd/*.lock \
      /home/ubuntu/.android/avd/MobInspect_AVD.avd/*.lock.lock \
      /home/ubuntu/.android/avd/MobInspect_AVD.avd/snapshot.lock* \
      /home/ubuntu/.android/avd/MobInspect_AVD.avd/*.tmp* 2>/dev/null || true
sudo systemctl start mobinspect-avd.service
```

## Recovery: web service unresponsive after a restart

If gunicorn is listening but every request times out — usually a worker-init hang.

```bash
journalctl -u mobinspect.service --no-pager -n 80 | grep -iE "error|loading|traceback"
```

Most common cause we've hit: `~/.MobInspect/config.py` has a value that imports-but-hangs inside gunicorn's worker (e.g., `ANALYZER_IDENTIFIER` directly in the config file rather than via systemd env). Set it via the drop-in instead.

## Disaster recovery

`~/.MobInspect/db.sqlite3` is the single physical file holding the audit log, RBAC assignments, hashed API keys, scan history, and user accounts. Lose it and you've lost the install. We protect it in two layers — hourly **on-host** SQLite snapshots and a daily **off-host** restic push — with a one-command interactive restore.

### Targets

| Metric | Target | Mechanism |
|--------|--------|-----------|
| RPO (recovery-point objective) | **≤ 1 hour** | `mobinspect-backup.timer` runs `OnCalendar=hourly`, `Persistent=true` so a missed run fires on next boot |
| RTO (recovery-time objective) | **≤ 15 minutes** | `deploy/scripts/restore.sh` is interactive but the path is: pick snapshot → stop unit → copy file → restart unit |
| Retention (local snapshots) | 14 days hourly (~336 files) | `find … -mtime +14 -delete` inside the service `ExecStart` |
| Retention (off-host, when configured) | 24h hourly + 14d daily + 8w weekly + 12m monthly | `restic forget --prune` policy in `deploy/scripts/restic-offsite.sh` |

### Install the hourly snapshot timer

The two unit files live in the repo at `deploy/systemd/`. Copy them into `/etc/systemd/system/` (or symlink) and enable:

```bash
sudo cp deploy/systemd/mobinspect-backup.service /etc/systemd/system/
sudo cp deploy/systemd/mobinspect-backup.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mobinspect-backup.timer
# Verify
systemctl list-timers mobinspect-backup.timer
sudo systemctl start mobinspect-backup.service        # one-shot smoke test
ls -lh /var/backups/mobinspect/                       # expect a db-YYYYMMDD-HHMMSS.sqlite3
```

The service uses SQLite's online `.backup` command, which acquires a shared lock — it is **safe to run while gunicorn and the django-q2 worker are live**. No downtime, no risk of a torn copy. The unit also ships with `MemoryMax=512M`, `Nice=10`, and best-effort low IO priority so a snapshot can't starve the web service.

### Off-host shipping (restic) — recommended, not auto-installed

`deploy/scripts/restic-offsite.sh` is a **stub** because the repository URL, credentials, and bandwidth budget are per-deployment. The header comment of that script lists the exact `/etc/mobinspect/restic.env` keys it expects and the `restic init` step you run once. Wire it to its own daily timer (don't piggy-back on the hourly one — restic pushes are minutes, not seconds, and don't need hourly cadence).

### Restoring from a snapshot

```bash
sudo deploy/scripts/restore.sh
```

The script:

1. Lists every `db-*.sqlite3` snapshot under `/var/backups/mobinspect/`, newest first, with size + mtime.
2. Prompts for an index, then a `yes` confirmation.
3. Stops `mobinspect.service` **and** `mobinspect-worker.service` (`PartOf=` propagates stop/restart but **not** start, so both have to be cycled explicitly — otherwise async scans queue forever after the restore).
4. Side-copies the *current* `db.sqlite3` to `db.sqlite3.pre-restore-<ts>` so you can roll forward again if the chosen snapshot is wrong.
5. `install`s the snapshot in place with `0640 ubuntu:ubuntu`, then `chown -R ubuntu:ubuntu /home/ubuntu/.MobInspect`.
6. Restarts `mobinspect.service` + `mobinspect-worker.service` and tails 20 lines of journal so you can see it come back healthy.

If the service does not come back healthy, the script prints the exact three commands to roll back to the pre-restore copy.

### Quarterly DR drill (do not skip)

A backup that has never been restored is a wish, not a recovery plan. Once per quarter, on a non-production host (or after-hours on prod with the team aware):

1. `sudo deploy/scripts/restore.sh` — pick a snapshot from ~6h ago.
2. Log in as `superadmin`, confirm the audit log, RBAC roles, and scan history all came back.
3. Roll forward to the pre-restore copy using the printed commands.
4. Record the drill outcome (date, snapshot age, RTO actually achieved) in the `## Postmortems` section at the bottom of this runbook.

## Operations

### Health probes

Two unauthenticated endpoints land in `mobsf/MobSF/views/healthz.py`:

| Route | Probes | Use for |
|-------|--------|---------|
| `GET /readyz` | none — just confirms the process is up | k8s/podman liveness, load-balancer fast path |
| `GET /healthz` | DB `SELECT 1`, `django_q.Schedule.objects.exists()`, `adb devices` (2 s timeout) | Prometheus blackbox, uptime monitors, the "is this box actually able to serve scans?" question |

```bash
# Quick eyeball
curl -s http://127.0.0.1:8001/healthz | jq .
# Exit non-zero if degraded — wire this into your monitor
curl -fs http://127.0.0.1:8001/healthz | jq -e '.status == "ok"' >/dev/null
```

Semantics:

- `status="ok"` — every probe passed.
- `status="degraded"` — DB ok but queue **or** adb failed. Web still serves and static scans queue; dynamic / async scans will stall until the failing component is fixed.
- `status="failed"` — DB probe failed. The service is effectively down; the HTTP response is still 200 (the endpoint is for monitors, not for circuit-breaking) but `.status` is `failed`.

`/healthz` is intentionally **CSRF-exempt and never cached** — your monitor talks to it from outside the auth session.

### TLS termination (recommended for any non-LAN exposure)

`gunicorn` on `0.0.0.0:8001` is **plain HTTP**. For anything beyond a trusted LAN, front it with nginx (or Caddy) and set:

```bash
sudo systemctl edit mobinspect.service
# add:
# [Service]
# Environment=MOBINSPECT_BEHIND_TLS=1
# Environment=MOBINSPECT_BEHIND_PROXY=1
# Environment=MOBINSPECT_ALLOWED_HOSTS=mobinspect.example.com
sudo systemctl daemon-reload && sudo systemctl restart mobinspect.service
```

`MOBINSPECT_BEHIND_TLS=1` switches on `Secure` cookies + HSTS + the secure CSRF/session flags. `MOBINSPECT_BEHIND_PROXY=1` honors `X-Forwarded-*` headers so Django sees the original client IP / scheme. **Never** flip `BEHIND_TLS=1` without an actual TLS terminator in front — the secure-cookie flag will lock users out over plain HTTP.

### Useful journalctl queries

```bash
# Last 200 lines, all three units, with timestamps
journalctl -u mobinspect.service -u mobinspect-worker.service -u mobinspect-avd.service -n 200 --no-pager

# Audit-signal stream (failed logins, role changes, API auth failures)
journalctl -u mobinspect.service --no-pager | grep -E 'audit\.event|api\.auth\.fail|admin\.user\.'

# Just the slow-request warnings from gunicorn
journalctl -u mobinspect.service --no-pager | grep -iE 'WORKER TIMEOUT|killing worker'

# Backup timer history
journalctl -u mobinspect-backup.service --since '24 hours ago' --no-pager

# AVD boot trace
journalctl -u mobinspect-avd.service --since '10 minutes ago' --no-pager | grep -E 'boot_completed|emulator: ERROR|VERBOSE'
```

### Audit log verification

The `AuditEvent` table is a SHA-256 hash chain with a SQLite `BEFORE UPDATE` / `BEFORE DELETE` trigger that aborts mutations. Verify integrity any time you suspect tampering, and as the final step of any restore:

```bash
poetry run python manage.py audit_verify   # exit 0 = chain intact
```

Re-seal after a (deliberate) bulk import by re-running the command — it walks the chain forwards and reports the first broken link.

## Upgrade flow

```bash
ssh ubuntu@<host>
cd ~/MobInspect
git pull
poetry install                                   # only if pyproject.toml changed
./scripts/tailwind-build.sh                      # only if any template/CSS changed
poetry run python manage.py migrate --noinput    # only if new migrations
# If a unit file or drop-in changed in deploy/systemd/, you MUST re-install it
# (see "Installing / updating the systemd units" below). git pull updates the
# repo copy, not the live unit under /etc/systemd/system/ — daemon-reload alone
# re-reads /etc/, so it picks up nothing until the file is copied across.
sudo systemctl daemon-reload                     # only after re-installing a changed unit/drop-in
sudo systemctl restart mobinspect.service        # worker auto-cycles via PartOf=
```

The AVD unit does *not* restart on a code update — restart it only when the AVD definition or emulator binary version changes.

### Installing / updating the systemd units

The unit + drop-in files in `deploy/systemd/` are the **source of truth**, but they are
**not** the files systemd runs. systemd only ever reads `/etc/systemd/system/`.
`git pull` (or editing the repo file directly) changes the repo copy and has **zero
effect on the running service** — and `daemon-reload` re-reads `/etc/`, so it won't
pick up a repo-only edit either. You must copy the file across first.

Use `install` (not `cp`) so ownership/mode are set explicitly and the copy is atomic:

```bash
cd ~/MobInspect

# Core units
sudo install -m 0644 deploy/systemd/mobinspect.service        /etc/systemd/system/mobinspect.service
sudo install -m 0644 deploy/systemd/mobinspect-worker.service /etc/systemd/system/mobinspect-worker.service
sudo install -m 0644 deploy/systemd/mobinspect-avd.service    /etc/systemd/system/mobinspect-avd.service

# Drop-in (the directory must exist first)
sudo install -d -m 0755 /etc/systemd/system/mobinspect.service.d
sudo install -m 0644 deploy/systemd/mobinspect.service.d/avd.conf \
  /etc/systemd/system/mobinspect.service.d/avd.conf

# Re-read unit files, then restart the affected services
sudo systemctl daemon-reload
sudo systemctl restart mobinspect.service        # worker auto-cycles via PartOf=
sudo systemctl restart mobinspect-avd.service    # only if the AVD unit changed
```

After re-installing, **confirm the new resource ceilings actually applied** —
`daemon-reload` updates the unit on disk but some cgroup properties only take full
effect on the next (re)start:

```bash
# Expect 8589934592 (8G) for the web unit, 4294967296 (4G) for the worker,
# 6442450944 (6G) for the AVD. "infinity" means the hardened unit is NOT live yet.
systemctl show mobinspect.service        -p MemoryMax -p MemoryHigh -p TasksMax
systemctl show mobinspect-worker.service -p MemoryMax -p MemoryHigh -p TasksMax
systemctl show mobinspect-avd.service    -p MemoryMax -p MemoryHigh

# Sandbox/exposure score (target ≤ 5.0)
systemd-analyze security mobinspect.service
```

If `MemoryMax` still shows `infinity` after a restart, the live unit is the old
pre-hardening copy — re-run the `install` step above; you almost certainly edited the
repo file without copying it to `/etc/systemd/system/`.

---

## Dynamic analysis: writable /system + host requirements (2026-06-12)

Android dynamic analysis needs the emulator's `/system` partition writable so
`mobsfy_init` can push the Frida server + CA. On API 30 that requires disabling
dm-verity, which **only takes effect after a guest reboot**.

**Provisioning (capable host):** `deploy/scripts/avd-provision.sh` + the
`mobinspect-avd-provision.service` oneshot make `/system` writable once per cold
boot (wait boot → `adb root` → `adb disable-verity` → `adb reboot` → `adb root`
→ `adb remount`). Install:

```bash
sudo install -m 644 deploy/systemd/mobinspect-avd-provision.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mobinspect-avd-provision.service
journalctl -u mobinspect-avd-provision.service -f   # watch for "/system is now WRITABLE"
```

**HOST REQUIREMENT — verified the hard way.** The host's KVM must be able to
**reboot the emulator guest**. On the `192.168.2.118` staging box (an ESXi
nested-virt guest) this was tested repeatedly and the AVD **wedges on every
second boot**: a freshly-wiped overlay cold-boots fine (~90 s), `disable-verity`
succeeds, but the subsequent reboot (warm `adb reboot` *or* cold qemu restart)
hangs the guest indefinitely — it goes `offline` and never reaches
`sys.boot_completed`. Root cause is the qcow2 overlay + nested-virt I/O path,
not MobInspect code. **Consequence: dynamic analysis is NOT achievable on this
host.** Static analysis (APK + IPA), RBAC, audit, API, malware/tracker
enrichment, and analytics are all unaffected and working.

To actually run dynamic analysis, use one of:
- bare-metal Linux with KVM (emulator reboots reliably),
- a properly-provisioned nested-virt host (full VT-x/EPT + adequate disk I/O),
- Genymotion, or
- a physical Android device over adb (set `ANALYZER_IDENTIFIER=<ip:port>`).
