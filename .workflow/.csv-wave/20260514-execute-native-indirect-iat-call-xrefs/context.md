# Native Indirect IAT Call Xrefs Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-E Indirect Import Calls

## Completed

- Added native decoding for `ff 15 disp32` as `call qword ptr [rip+disp32]`.
- Reused decoded `data_target` to resolve indirect calls through PE Import Address Table slots.
- Extended native xref generation so `call [rip+disp32]` can emit function -> import `CALLS_IMPORT` when the data target matches a known import slot.
- Updated native function call counts for resolved indirect import calls.
- Added a focused unit test for indirect IAT import calls.
- Updated README capability text to mention `ff 15 disp32` indirect import calls.

## Native-Only Constraint

This slice uses RevDeck's in-process decoder and native import target map. It does not call external reverse-engineering CLIs, introduce compatibility adapters, or add import-json workflows.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

Indirect import recovery currently covers RIP-relative `ff 15 disp32`. Future native analyzer slices should add more ModRM/SIB forms, `jmp [rip+disp32]` import thunks, delay-load imports, relocation-backed references, and architecture-specific decoder modules.
