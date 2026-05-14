# Plan Report -- M1 SDK Contract Preview

## Objective

Continue from the plugin SDK brainstorm into a concrete execution plan for RevDeck's first local plugin SDK preview.

## Scope

M1 implements the foundation only:

- Plugin manifest validation and inspection.
- Stable ObjectBatch schemas and dry-run validation.
- Default-deny permission model and safety skeleton.
- Plugin run audit records.
- CLI commands: `revdeck plugin validate`, `revdeck plugin inspect`, `revdeck plugin test`.
- Minimal conformance fixtures under `tests/plugin-sdk`.

## Non-Goals

- Public marketplace.
- Real OS sandbox hardening beyond a safety skeleton.
- Fully custom TUI plugin renderers.
- Direct SQLite access for plugins.
- Full plugin ObjectBatch commit unless dry-run and transaction safety are complete.

## Exploration Summary

### Architecture

Use `crates/revdeck-plugin-sdk` for public manifest/ObjectBatch contracts and `crates/revdeck-plugin-host` for dry-run, permission checks, runner skeleton, and run audit. Reuse `ObjectRef`, `StableObjectKey`, `AnalysisRunRepository`, and object repositories.

### Implementation

Follow workspace crate conventions, serde snake_case enums, structured validation reports, and existing integration-test crate layout. Add explicit `toml` and `semver` workspace dependencies.

### Integration

Add nested plugin CLI commands in `revdeck-cli`; keep CLI thin. Add `plugin_runs` audit schema in `revdeck-db`. Keep plugin lifecycle separate from artifact-wide `latest_analysis_run`.

### Risk

Do not overclaim sandboxing. M1 must be explicit: default-deny permissions, no direct DB writes, no process launch unless granted, dry-run first, sanitized diagnostics, deterministic digest tests.

## Plan

Execution plan lives at:

`.workflow/scratch/20260513-plan-m1-sdk-contract-preview/plan.json`

Task files live under:

`.workflow/scratch/20260513-plan-m1-sdk-contract-preview/.task/`

## Waves

1. Workspace foundation: TASK-001.
2. Manifest and ObjectBatch contracts: TASK-002.
3. Plugin run audit schema: TASK-003.
4. Host safety skeleton: TASK-004.
5. CLI plugin commands: TASK-005.
6. Conformance harness: TASK-006.
7. README and verification: TASK-007.

## Verification Gate

Final execution must pass:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
revdeck plugin validate fixtures/plugins/valid-minimal/revdeck-plugin.toml
revdeck plugin inspect fixtures/plugins/valid-minimal/revdeck-plugin.toml
revdeck plugin test fixtures/plugins/valid-minimal
```
