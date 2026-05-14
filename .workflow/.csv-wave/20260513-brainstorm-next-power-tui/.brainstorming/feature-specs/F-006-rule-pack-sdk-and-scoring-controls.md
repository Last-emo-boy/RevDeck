# F-006 Rule Pack SDK And Scoring Controls

Priority: P1

## Summary

Allow first-party and plugin rule packs to emit explainable score reasons. This should extend Function Radar without opaque black-box scores.

## Must Have

- Rule packs emit reason code, label, contribution, confidence, evidence refs, and provider.
- Users can suppress noisy reason codes or providers.
- Scoring replay is deterministic.
- Function Radar and Inspector display provider attribution.

## Acceptance

- A fixture rule pack adds a new score reason visible in Function Radar.
- Suppression removes or lowers a reason without deleting evidence.
