# Native IAT Jump Thunk Xrefs Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-F Import Jump Thunks

## Completed

- Added native decoding for `ff 25 disp32` as `jmp qword ptr [rip+disp32]`.
- Reused decoded `data_target` to resolve jump thunks through PE Import Address Table slots.
- Extended native xref generation so `jmp [rip+disp32]` import thunks emit function -> import `CALLS_IMPORT` when the data target matches a known import slot.
- Updated native function call counts for resolved import jump thunks.
- Added a focused unit test for IAT jump thunk xrefs.
- Updated README capability text to mention `ff 25 disp32` import thunks.

## Native-Only Constraint

This slice uses RevDeck's in-process decoder and native import target map. It does not call external reverse-engineering CLIs, introduce compatibility adapters, or add import-json workflows.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

Import thunk recovery currently covers RIP-relative `ff 25 disp32`. Future native analyzer slices should add more ModRM/SIB forms, delay-load imports, relocation-backed import references, and architecture-specific decoder modules.
