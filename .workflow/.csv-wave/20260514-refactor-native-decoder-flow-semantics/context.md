# Native Decoder Flow Semantics Refactor

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-G Decoder Semantics Foundation

## Completed

- Added an internal `InstructionFlow` enum for decoded instruction semantics:
  - `None`
  - `Call`
  - `Jump`
  - `ConditionalBranch`
  - `Return`
- Moved branch / terminal / flow-kind decisions off mnemonic string matching.
- Kept persisted `flow_kind` metadata stable by mapping enum values back to the existing strings:
  - `call`
  - `jump`
  - `conditional_branch`
- Updated CFG leader, block splitting, fallthrough, and xref logic to use flow semantics.
- Added a focused decoder test that verifies flow semantics for direct calls, indirect IAT calls, IAT jump thunks, conditional branches, and returns.

## Native-Only Constraint

This is an internal native analyzer refactor. It does not call external reverse-engineering CLIs, introduce compatibility adapters, or add import-json workflows.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

The decoder still lives in the indexer module. Future slices should move x86/x64 decoding into a dedicated module, add typed operand facts, and split instruction semantics from persistence conversion.
