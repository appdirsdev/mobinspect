# MobInspect — Project Memory (portable copy)

This folder is a **verbatim copy of the Claude Code project memory** for MobInspect,
placed inside the repo so it travels with the project to another machine. It is the
notes Claude uses to recall how this project is built, deployed, and operated.

Last synced from the live memory: **2026-07-23**.

On this Mac the live copy lives at:

    ~/.claude/projects/-Users-vipin-Appdirs-projects-mac-mini-projects-MobInspect/memory/

## Index

See [`MEMORY.md`](MEMORY.md) — it lists every topic file with a one-line hook.
Each other `.md` is one topic (frontmatter + body, with `[[wikilinks]]` between
them). The index is the single source of truth for what's here, so this README no
longer duplicates the file list (which drifted out of date).

Current highlights (2026-07): the `tests_e2e/` Playwright+API suite (187 tests) +
100% owned-code backend coverage (2384 tests); the full Docker deployment on
192.168.3.64 (`docker-64-ai-fix.md`) with host bind-mount persistence and
`admin`/`‹SSH-SUDO-PW›` login; the repo reorg and the resolved `/find/` + blank-email
bugs. See `MEMORY.md`.

## Restoring this memory on a new machine

Claude Code stores project memory under `~/.claude/projects/<encoded-path>/memory/`,
where `<encoded-path>` is the project's absolute path with every `/` replaced by `-`.

1. Clone this repo onto the new machine and open it once in Claude Code (this
   creates the `~/.claude/projects/<encoded-path>/` directory).
2. Copy these files into place. For the current absolute path it is:

       mkdir -p ~/.claude/projects/-Users-vipin-Appdirs-projects-mac-mini-projects-MobInspect/memory
       cp project-memory/*.md ~/.claude/projects/-Users-vipin-Appdirs-projects-mac-mini-projects-MobInspect/memory/

   If the path differs, compute the encoded name from the new absolute path
   (replace `/` with `-`) and copy into `~/.claude/projects/<that>/memory/`.
3. Or simplest: open the project in Claude Code and say
   *"import project-memory/ into my project memory"* — it will place them correctly.

Keep this copy in sync by re-copying whenever the live memory changes:

    cp ~/.claude/projects/-Users-vipin-Appdirs-projects-mac-mini-projects-MobInspect/memory/*.md project-memory/
