---
name: verify-dont-trust-agent-reports
description: User explicitly asked for an honest re-audit after subagent-reported numbers; always independently reproduce significant/quantitative claims before relaying them
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 5ab6296a-a4ff-4666-ac3f-9b3248f9fe76
---

After a multi-agent session built `tests_e2e` and a subagent reported "98.8%
backend coverage" (and later "100%" from a follow-up agent), the user's next
message was: **"do audit and check the entire coverage with honestly."**
That's a direct signal: subagent self-reports of quantitative/success claims
are not sufficient to relay to the user as fact — they must be independently
re-verified.

**Why it mattered here, concretely:** the first coverage number (98.8%,
148 missing) turned out to be an ARTIFACT of a `--reuse-db` corrupted test
database (see [[coverage-campaign]]), not a real gap. A later agent's "100%,
0 missing, no code changes" was ALSO surprising enough to warrant
independent re-verification — I reran the exact command myself, twice, on
two separate fresh databases, watched the process complete via `Monitor`
(not just trusted the agent's final message), and got byte-identical
results both times before reporting it as fact.

**How to apply this pattern going forward, in this project or any other:**
- Any number a subagent reports (coverage %, test pass counts, "N bugs
  found") — rerun the measurement yourself when it's material to what you
  tell the user, especially if the number is surprising (unexpectedly
  round, unexpectedly perfect, or a big jump with no code changes to
  explain it).
- Spot-check at least one or two of the subagent's specific claims against
  live reality (I reproduced the exact `/find/` 500 traceback, the
  `RegisterForm` blank-email bug, and the enclave-host rejection myself via
  curl/ORM queries rather than taking the agent's word).
- Check for git hygiene after any agent-driven file reorg — a prior
  `git reset` mid-session had silently left `tests_ui/` deletions
  unstaged/uncommitted even though the new `tests_e2e/` files landed; this
  wasn't caught until an explicit audit pass.
- When a subagent's task involves a long-running background process, don't
  accept "I'll wait for a monitor" as a final answer if you can check the
  process/log directly yourself with Bash — subagents sometimes yield
  without actually blocking to completion.

**Related standing instruction from the user, reinforced twice this
session:** any structural/reorg change ("proper folder structure") must be
followed by actual end-to-end verification (test suite reruns, live smoke
tests) before being reported as done — "nothing broken" is a claim to prove,
not assume. See [[repo-reorg-2026-07-21]] for the verification method this
produced.
