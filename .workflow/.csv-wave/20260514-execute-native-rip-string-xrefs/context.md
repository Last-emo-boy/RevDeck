# Native RIP-Relative String Xrefs Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-C RIP-Relative Data References

## Completed

- Extended native decoded instruction facts with `data_target` metadata.
- Added conservative x64 RIP-relative data reference decoding for common forms:
  - `48 8d 05 disp32` -> `lea reg,[rip+disp32]`
  - `48 8b 05 disp32` -> `mov reg,[rip+disp32]`
  - `8d 05 disp32` -> `lea reg,[rip+disp32]`
  - `8b 05 disp32` -> `mov reg,[rip+disp32]`
- Added native string target indexing by virtual address.
- Added native xref generation when a decoded RIP-relative data target resolves to an indexed string:
  - instruction -> string `REFERENCES`
  - function -> string `REFERENCES`
- Updated native function `string_count` from resolved string references with per-function de-duplication.
- Added a focused native CFG aggregation test that verifies instruction metadata, xref creation, and string count updates.
- Updated README capability text to include RIP-relative string xrefs.

## Native-Only Constraint

This slice keeps RevDeck on the native analyzer path. It does not call external reverse-engineering CLIs and does not add compatibility adapters, import-json flows, or external disassembler fixtures.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

Data reference recovery is still a conservative direct-address subset. Future native analyzer slices should resolve relocation-backed operands, import address table references, stack/local references, and more ModRM/SIB forms.
