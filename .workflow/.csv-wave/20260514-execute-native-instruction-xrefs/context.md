# Native Instruction Xrefs Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-B Instruction-Driven Xrefs

## Completed

- Extended native instruction facts with decoded target address and flow kind metadata.
- Added native xref generation from decoded control-transfer instructions:
  - `call rel32` produces function -> function `CALLS` xrefs when the target matches a known function start.
  - `jmp` / `jcc` produce instruction -> basic block or instruction -> function `REFERENCES` xrefs when the target is resolvable.
- Reused the existing `xrefs` and `edges` persistence path so Graph Lab, `:xrefs current`, scoring, and relation queries can consume the new native facts without an adapter layer.
- Updated native function `call_count` from decoded call xrefs.
- Added focused tests for conditional branch xrefs and native function call xrefs.
- Updated README capability text to describe basic native call / branch xref support.

## Native-Only Constraint

This slice does not introduce external reverse-engineering CLI calls, radare2 compatibility code, import-json workflows, or adapter fixtures. It builds on RevDeck's native analyzer pipeline and existing SQLite project model.

## Verification Target

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- External adapter grep audit over `README.md crates tests fixtures .workflow`

## Remaining Limitation

The decoder is still intentionally conservative. The next native analyzer slices should broaden instruction coverage, recover memory references and indirect call hints, and use relocation/import tables to resolve call targets beyond direct relative control flow.
