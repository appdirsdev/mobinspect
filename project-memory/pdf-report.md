---
name: pdf-report
description: How the MobInspect PDF export works + the wkhtmltopdf/Qt-WebKit gotchas that were fixed to make it render professionally & identically on macOS + Linux
metadata: 
  node_type: memory
  type: project
  originSessionId: cc2a3ba9-0869-4596-b93d-e1550cf847c2
---

PDF export (`/pdf/<md5>/`) renders `mobsf/templates/pdf/{android,ios,windows}_report.html` via **pdfkit → wkhtmltopdf 0.12.6** (options in `mobsf/StaticAnalyzer/views/common/pdf.py`: Letter, Landscape, `enable-local-file-access`). Needs `wkhtmltopdf` (see [[toolchain]]; env `MOBSF_WKHTMLTOPDF_BINARY` → `settings.WKHTMLTOPDF_BINARY`, else PATH).

**wkhtmltopdf 0.12.6 uses an ancient Qt 4.8 WebKit** (~2012). The stock templates were authored for a modern browser and rendered badly (invisible cover band, garbled overlapping labels, dropped letters). All fixed by editing the templates + options:

1. **CSS custom properties (`var(--x)`) are NOT supported** → every themed color was dropped, leaving black-on-white with a few rgba() accents. Fixed by substituting all `var(--token)` with literal hex (android uses `--critical`/`--brand`/`--line`… ; windows uses `--c-*` names).
2. **`linear-gradient()` backgrounds don't render** → the cover band was white (white title invisible). Fixed → solid `background-color`.
3. **CSS `filter: brightness(0) invert(1)`** (used to whiten the logo) is ignored → replaced the logo `<img>` with a white text wordmark.
4. **`min-width` on `display:inline` is a no-op** → the `.info-list h5` labels overlapped their values ("File Name:nDrive…"). Fixed → `display:inline-block; width:178px`.
5. **BROKEN BUNDLED FONTS + `local()` trap (the big cross-platform bug):** the bundled `Oswald-Regular.ttf` AND `Open_Sans/OpenSans-Regular.ttf` were subset/broken (missing uppercase D/F/G/H/K/V…). `src: local('Open Sans'), url(...)` masked it on **macOS** (system font rescued it) but on **Linux** (no system font) it would render broken. Fixed by: dropping Oswald (→ Open Sans everywhere), **replacing the bundled OpenSans-Regular.ttf/Bold.ttf with complete fontsource TTFs**, and **stripping all `local()` hints** so the bundled url() TTF is always used → identical on macOS+Linux.
6. **WEBP app icons don't decode** in Qt-WebKit → showed a broken box. Fixed → template falls back to `no_icon.png` when `icon_path` contains `.webp` (no Pillow available to convert).
7. **Async @font-face load race** → text (esp. the white cover title/wordmark) intermittently dropped, AND content near the `#cover { margin:-0.5in }` bleed edge clipped. Fixed → `javascript-delay: 1000` + `no-stop-slow-scripts` in options, and bumped `.cover-band` top padding to clear the bleed.

**Verify a PDF renders right:** `curl -b cookies /pdf/<md5>/ -o r.pdf`; rasterize with `pdftoppm -png -r 85 -f 1 -l 1 r.pdf out` (needs `brew install poppler`) and READ the png — do NOT trust `pdftotext` for the cover (its `letter-spacing` splits words → false negatives). Render 2–3× to catch races.

**Django `{# #}` comments are SINGLE-LINE ONLY** — a multi-line `{# … #}` renders as visible text (bit me in base/app.html "on top of the portal" and in the pdf icon comment). Use `{% comment %}`/`<!-- -->`/CSS `/* */` for multi-line.

Related: [[toolchain]], [[da-ui-port]].
