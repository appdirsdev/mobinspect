# Memory Index

- [Server deployment](server-deployment.md) — prod server has a DHCP IP that moves on restart: find it with `./prod.sh` (host-key scan); ALLOWED_HOSTS is self-healing on-server (boot oneshot + 2-min watch timer, reboot-proven); nginx :80→gunicorn, rsync deploy from Mac, gunicorn 25.1.0 fork-deadlock fix
- [Toolchain](toolchain.md) — how the MobInspect dev env is installed (Python 3.13.5/pyenv, Poetry, Postgres 16, Android SDK/AVD, admin creds)
- [Start script](start-script.md) — `./start.sh` single launcher; Postgres never restarted/stopped by it
- [Dynamic Analysis fixes](dynamic-analysis-fixes.md) — TCP id 127.0.0.1:5555 + API 30 emulator + Frida-server must run from /data/local/tmp (not /system) or spawn fails with libart.so
- [Compare & fonts](compare-and-fonts.md) — scan-compare has no UI button (Android-only); added missing web fonts; title-noise silenced
- [DA UI port](da-ui-port.md) — which Dynamic Analysis templates are on the new design system vs still legacy; the legacy_app.html pattern; `key` filter is global
- [PDF report](pdf-report.md) — wkhtmltopdf/Qt-WebKit gotchas (no var()/gradient/filter, broken bundled fonts + local() trap, webp icons, font-load race) fixed for pro + cross-platform (Linux) rendering; Django `{# #}` is single-line only
- [Dark-mode theming](ui-theming.md) — how white-in-dark-mode was fixed: global Bootstrap override in legacy_app + shared widget override in base/app.html
- [Branding](branding.md) — redesigned logo (shield + magnifier + check); assets favicon.svg/logo.svg + reusable components/logo_mark.html include
