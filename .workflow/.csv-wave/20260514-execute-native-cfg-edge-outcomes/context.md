# Wave Context: native cfg edge outcomes

## Goal

Carry native conditional branch outcomes from instruction facts into CFG edge metadata, then render that evidence in the TUI Local Graph.

## Changes

- Extended parsed CFG edge facts with optional `condition_summary` and `known_outcome`.
- Persisted CFG condition metadata into both object graph control-flow edges and indexed CFG edge records.
- Derived branch/fallthrough edge outcome metadata from native conditional branch summaries:
  - branch edges receive `known_outcome = "taken"` when the branch is statically known taken.
  - fallthrough edges receive `known_outcome = "not_taken"` when the branch is statically known not taken.
- Rendered control-flow relation lines in Local Graph with edge kind, known outcome, and condition summary.
- Added focused index coverage for known taken branch edges and known not-taken fallthrough edges.
- Added focused TUI coverage for Local Graph control-flow outcome rendering.

## Verification

- `cargo test -p revdeck-index native_cfg_edges_preserve_condition_summary_and_known_outcome -- --nocapture`
- `cargo test -p revdeck-tui-tests graph_lab_renders_control_flow_condition_outcomes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice keeps the analyzer native-only. The condition evidence now travels from decoded instruction facts into CFG graph edges, so graph navigation can explain why a branch or fallthrough edge is likely active.
