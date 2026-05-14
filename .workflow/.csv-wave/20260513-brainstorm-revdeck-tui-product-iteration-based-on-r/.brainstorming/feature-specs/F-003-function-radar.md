# F-003 Function Radar

## Intent
Help analysts decide what to inspect first. Function Radar MUST rank functions and show explainable reasons for every score.

## Scope
- Function list with score, name/address, size, call count, string count, and reason labels.
- Scoring signals for sensitive strings, dangerous imports, xrefs, size, entrypoint proximity, and user tags.
- Sort/filter/search over ranked functions.

## Acceptance Signals
- Scoring is deterministic for fixtures.
- Each score has visible reasons.
- Selecting a function updates inspector context.
- Analysts can jump from a function to related strings/imports/xrefs.

## Dependencies
F-001, F-002, F-004.
