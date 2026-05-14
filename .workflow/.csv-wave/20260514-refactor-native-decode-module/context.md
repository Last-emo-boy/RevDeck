# Native Decode Module Refactor

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-H Decoder Module Boundary

## Completed

- Split native instruction decoding out of `crates/revdeck-index/src/lib.rs`.
- Added `crates/revdeck-index/src/native_decode.rs`.
- Moved decoder-only types and helpers into the new module:
  - `DecodedInstruction`
  - `InstructionFlow`
  - `decode_native_instructions`
  - `bytes_hex`
  - relative branch / RIP-relative helper routines
- Kept the module crate-private so the analyzer can evolve without exposing a public API prematurely.
- Preserved existing persisted instruction metadata and `flow_kind` strings.
- Kept focused decoder and CFG/xref tests passing after the move.

## Native-Only Constraint

This slice is a native analyzer refactor. It does not call external reverse-engineering CLIs, introduce compatibility adapters, or add import-json workflows.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

The decoder is now isolated, but typed operand facts are still implicit fields on `DecodedInstruction`. Future slices should introduce an operand enum and separate x86/x64 opcode families inside the module.
