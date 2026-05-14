# Native PE IAT Import Xrefs Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-D PE IAT Import References

## Completed

- Added native PE import address recovery from the PE import descriptor and thunk tables using the Rust `object` crate's low-level PE parser.
- Backfilled `ParsedImport.address` with the image-base-adjusted Import Address Table slot when available.
- Added import target indexing by virtual address.
- Extended native instruction xref generation so direct `call` targets can resolve to imports and emit function -> import `CALLS_IMPORT` xrefs.
- Updated native function call counts for resolved import calls.
- Added focused tests for PE IAT slot recovery and native `CALLS_IMPORT` xref generation.
- Updated README capability text to include PE IAT import xrefs and cleaned the plugin manifest example so it no longer suggests an external tool adapter path.

## Native-Only Constraint

This slice remains native analyzer work. It uses in-process Rust parsing of PE structures and does not call external reverse-engineering CLIs, add compatibility adapters, or add import-json workflows.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

Import call recovery currently resolves direct calls to known IAT slot addresses. Future slices should add indirect call decoding such as `ff 15 disp32`, relocation-backed import references, delay-load imports, and richer import thunk metadata.
