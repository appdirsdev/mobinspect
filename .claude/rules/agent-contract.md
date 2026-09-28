# Agent contract (auto-loaded)

Before changing anything in this repository, read `docs/agent-contract/00-contract.md`,
then the workstream file you are executing, then the tail of `docs/agent-contract/PROGRESS.md`.
The contract's gates are mandatory; `DECISIONS.md` rows marked PENDING block the gates that depend on them.

## Hard rules (verbatim from the contract)

1. **Preserve behaviour.** Template edits leave existing `<script>` blocks byte-identical unless the workstream file names that script; chart datasets/labels/types, `{% url %}`, CSRF, form field names/ids, DataTable/EventSource/Alpine/CodeMirror hooks stay intact; diff against a captured baseline before claiming done.
2. **Never fabricate data.** No mock metrics, placeholder counts, or invented deltas. A page with nothing real to show shows nothing.
3. **Verify before claiming.** Every "done / fixed / passing" statement is preceded by the actual command and its pasted output. No output, no claim.
4. **Re-verify subagent reports independently.** A number or "all green" from a subagent is a hypothesis until the coordinator reruns the command.
5. **Image tests, not container tests.** Any Docker claim comes from a fresh container created from the built image (`docker rm` + `docker run`), never from a hot-patched running container.
6. **Honest coverage.** Report the real number; the known ceiling is about 67% (device/Windows/network-locked paths). Never delete or skip tests to raise it.
7. **Security invariants.** AI-generated text is never rendered with `|safe`; the deterministic `security_score` is never AI-written; severity colours are semantic-only; no new unauthenticated routes; `/tests/` gets auth.
8. **Credentials.** `admin/admin` and `.env.postgres` are local-only and never committed; no default credentials in any image; secrets only via env, `_FILE`, or generated-and-persisted.
9. **No credit lines.** No `Co-Authored-By`, "Generated with", or tool attribution in commits, code, docs, or release notes.
10. **Template comments use `{% comment %}`**, never HTML comments containing template syntax.
11. **One workstream per branch/PR; no drive-by refactors** inside rebrand or flow-fix commits (refactor is its own workstream and runs last).
12. **Stop at a gate you cannot pass.** Record the blocker in `PROGRESS.md` and end the session; never bypass (`--no-verify`, skipped tests, `force`).
