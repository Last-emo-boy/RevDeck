# F-005 Triage Queue And Finding Promotion

Priority: P1

## Summary

Turn radar leads and diagnostics into a review queue with states. Analysts can mark items reviewed, dismiss noise, or promote a lead into a finding with evidence pre-linked.

## Must Have

- Queue item states: new, investigating, reviewed, promoted, dismissed.
- Queue sources: radar score, dangerous import, sensitive string, weak boundary, parse warning, finding gap.
- `promote` action creates a finding draft with evidence.
- Triage Board shows counts and filters by state/source.

## Acceptance

- A high-risk function can become a finding draft in one action.
- Review state persists across TUI sessions.
