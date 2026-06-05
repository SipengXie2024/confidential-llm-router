# Audit-Feasibility Study

This directory implements P0-1: an empirical check of whether the small AEGIS
data plane is auditable.

## Protocol

1. Apply one seed patch from `seeded-defects/` to a clean throwaway worktree
   with `git apply --unidiff-zero <seed.patch>`.
2. Give the evaluator only `prompts/evaluator-prompt.md` and the patched
   worktree. Do not show `private/answer-key.csv`.
3. Record the transcript under `transcripts/<seed>/<auditor>.md` after removing
   secrets.
4. Score findings with `scripts/score-findings.py`.
5. Run the same prompt against the clean implementation to measure false
   positives.

Recommended auditors: at least two fresh-context coding agents plus one human
review pass. Missed defects are negative results and must remain in the final
summary.

## Current Pilot

The current pilot output is `raw/20260605T160257Z`. A fresh Codex reviewer
detected 8 of 10 seeded defects and produced no clean-implementation finding;
it missed S02 and S03. Claude Code was not run because the local approval
policy rejected exporting fixture source code to an external Claude service.

## Files

- `seeded-defects/`: controlled invariant-violation patches.
- `manifests/public-seeds.csv`: seed IDs and broad classes, no answer key.
- `private/answer-key.csv`: defect location and expected finding.
- `prompts/evaluator-prompt.md`: prompt shown to auditors.
- `summary-template.csv`: result schema for the paper detection matrix.
