# F-005 Scoring Rule And Triage Pack SDK

## Purpose

Let teams encode domain expertise into Function Radar and Triage Board without forking RevDeck.

## User Value

Analysts get explainable prioritization from team-specific rules: dangerous imports, network-to-command paths, auth strings, crash frequency, firmware routes, protocol hotspots, suspicious memory regions, and risky diffs.

## Requirements

- Plugins MUST emit score reasons, not opaque final scores.
- Every score reason MUST include provider, rule ID, rule version, contribution, confidence, source run, and evidence refs.
- Host aggregation computes final ordering and tie-breaking.
- Scores SHOULD support suppression, stale-run withdrawal, and deterministic rerun behavior.
- Opaque scores MUST NOT enter primary triage.

## SDK/Data Contracts

`ScoreReasonContribution`:

- `subject: ObjectRef`
- `provider: plugin_id`
- `rule_id`
- `rule_version`
- `contribution`
- `confidence`
- `evidence_refs`
- `explanation`
- `source_run_id`

## TUI/CLI Affordances

- Function Radar shows provider badges next to reasons.
- Inspector shows contribution, confidence, evidence count, provider, and run ID.
- Command Deck exposes `:rules list`, `:rules explain current`, and suppression flows later.

## Test Strategy

- Golden triage ordering and tie-breaking.
- Missing evidence rejection.
- Multi-plugin merge behavior.
- Suppression and stale score withdrawal tests.
- Deterministic rerun digest comparison.

## Rollout Notes

Implement after ObjectBatch and plugin run provenance exist. A first-party firmware-risk or dangerous-import rule pack is a good proof.
