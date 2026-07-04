---
name: branding
description: "MobInspect brand mark/logo — the redesigned assets, the reusable component, and where the brand appears"
metadata: 
  node_type: memory
  type: project
  originSessionId: cc2a3ba9-0869-4596-b93d-e1550cf847c2
---

MobInspect's logo was redesigned (was a generic blue rounded-square with an "M"+dot). **New mark concept:** a white security **shield** being **inspected by a magnifier** with a verified **checkmark** — i.e. "inspect mobile-app security & verify it." Premium blue gradient tile (#4F8DF9→#1B3AAE), magnifier in #2456D6, teal check accent #12C8A6. Wordmark "**Mob**Inspect" is two-tone: `Mob` in ink #0F172A + `Inspect` in brand blue #2456D6.

**Assets (edit these to change the brand):**
- `mobsf/static/mobinspect/img/favicon.svg` — the mark alone (64×64 tile). Browser tab icon (linked in `base/app.html`, `base/auth.html`), and `base/base_layout.html` brand image.
- `mobsf/static/mobinspect/img/logo.svg` — horizontal lockup (mark + two-tone wordmark, 300×72). Used by the **iOS/Windows PDF reports** (`pdf/{ios,windows}_report.html`). The **Android PDF cover** uses a plain white text wordmark instead (wkhtmltopdf SVG-gradient reliability — see [[pdf-report]]).
- `mobsf/templates/components/logo_mark.html` — **reusable inline SVG** of the mark. Use this for any in-app brand mark: `{% include "components/logo_mark.html" with cls="w-8 h-8" %}`. Used in `components/sidebar.html` and `base/auth.html` (replaced the old `bg-mobinspect-500` + lucide `shield-check` box). Its gradient ids are `mimarkTile`/`mimarkShield` — keep it to one instance per page to avoid SVG id collisions.

**Preview any SVG on macOS:** `qlmanage -t -s 420 file.svg -o /tmp/out` → produces `file.svg.png`. Static SVGs need a gunicorn reload (whitenoise re-indexes) to serve new bytes.

Not updated (optional): legacy `mobsf/static/img/favicon.ico` (raster fallback for browsers without SVG-favicon support) and `img/mobsf_logo.png` (unused in the new UI).

Related: [[pdf-report]], [[ui-theming]].
