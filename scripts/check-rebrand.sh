#!/usr/bin/env bash
# G-rebrand gate (docs/agent-contract/00-contract.md).
# Fails when any upstream-brand residue remains in tracked text files outside
# scripts/rebrand-allowlist.txt. Exit 0 = clean, 1 = residue found, 2 = misuse.
#
#   scripts/check-rebrand.sh            # list every residual line + per-file summary
#   scripts/check-rebrand.sh --quiet    # summary only
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

ALLOW="scripts/rebrand-allowlist.txt"
PATTERN='mobsf|mobile security framework|ajinabraham|opensecurity|mobinspecty|MobInspect_API30|github\.com/MobInspect/|mobinspect\.github\.io|join\.slack\.com/t/mobinspect'
QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1
[[ -f "$ALLOW" ]] || { echo "missing $ALLOW" >&2; exit 2; }

shopt -s nocasematch
hits="$(git grep -I -n -i -E "$PATTERN" -- . ":(exclude)$ALLOW" ':(exclude)scripts/check-rebrand.sh' || true)"

residual=""
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    path="${hit%%:*}"
    rest="${hit#*:}"
    text="${rest#*:}"
    allowed=0
    while IFS= read -r rule || [[ -n "$rule" ]]; do
        [[ -z "$rule" || "$rule" == \#* ]] && continue
        rule_path="${rule%%:*}"
        rule_text="${rule#*:}"
        if [[ "$path" =~ ^(${rule_path})$ ]] && [[ "$text" =~ ${rule_text} ]]; then
            allowed=1
            break
        fi
    done < "$ALLOW"
    (( allowed == 0 )) && residual+="$hit"$'\n'
done <<< "$hits"

residual="${residual%$'\n'}"
if [[ -z "$residual" ]]; then
    echo "REBRAND GATE: PASS (no residual upstream-brand references outside the allowlist)"
    exit 0
fi

count="$(printf '%s\n' "$residual" | wc -l | tr -d ' ')"
files="$(printf '%s\n' "$residual" | cut -d: -f1 | sort -u | wc -l | tr -d ' ')"
(( QUIET == 0 )) && printf '%s\n\n' "$residual"
echo "Residual lines by file:"
printf '%s\n' "$residual" | cut -d: -f1 | sort | uniq -c | sort -rn
echo
echo "REBRAND GATE: FAIL ($count residual lines in $files files)"
exit 1
