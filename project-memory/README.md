# MobInspect — Project Memory (portable copy)

This folder is a **verbatim copy of the Claude Code project memory** for MobInspect,
placed inside the repo so it travels with the project to another machine. On this
Mac the live copy lives at:

    ~/.claude/projects/-Users-vipin-appdirs-projects-MobInspect/memory/

These are the notes Claude uses to recall how this project is built, deployed, and
operated. `MEMORY.md` is the index; each other `.md` is one topic (frontmatter +
body, with `[[wikilinks]]` between them).

## Files

| File | What it covers |
|------|----------------|
| `MEMORY.md` | Index — one line per topic below |
| `server-deployment.md` | Prod server: DHCP IP that moves on reboot, `prod.sh` finder, **self-healing ALLOWED_HOSTS**, nginx→gunicorn, rsync deploy, gunicorn/billiard deadlock fixes |
| `toolchain.md` | Local dev env: Python 3.13.5/pyenv, Poetry, Postgres 16, Android SDK, wkhtmltopdf |
| `start-script.md` | `./start.sh` — the single local launcher |
| `dynamic-analysis-fixes.md` | Android DA: TCP adb id, API-30 image, frida-server `/data/local/tmp` fix |
| `compare-and-fonts.md` | Scan-compare UI, added web fonts, silenced template noise |
| `da-ui-port.md` | Which Dynamic Analysis templates are on the new design vs legacy |
| `pdf-report.md` | wkhtmltopdf/Qt-WebKit gotchas fixed for cross-platform PDF |
| `ui-theming.md` | How dark-mode white-boxes were fixed (two override layers) |
| `branding.md` | Redesigned logo assets + reusable `logo_mark.html` |

## Restoring this memory on the new Mac

Claude Code stores project memory under `~/.claude/projects/<encoded-path>/memory/`,
where `<encoded-path>` is the project's absolute path with every `/` replaced by `-`.

1. Copy/clone this repo onto the new Mac and open it once in Claude Code (this
   creates the `~/.claude/projects/<encoded-path>/` directory).
2. Copy these files into place. If the project lives at the **same absolute path**
   (`/Users/vipin/appdirs/projects/MobInspect`), it's just:

       mkdir -p ~/.claude/projects/-Users-vipin-appdirs-projects-MobInspect/memory
       cp project-memory/*.md ~/.claude/projects/-Users-vipin-appdirs-projects-MobInspect/memory/

   If the path differs, compute the encoded name from the new absolute path
   (replace `/` with `-`) and copy into `~/.claude/projects/<that>/memory/`.
3. Or simplest: open the project in Claude Code and say
   *"import project-memory/ into my project memory"* — it will place them correctly.

Keep this copy in sync by re-copying whenever the live memory changes
(`cp ~/.claude/projects/-Users-vipin-appdirs-projects-MobInspect/memory/*.md project-memory/`).
