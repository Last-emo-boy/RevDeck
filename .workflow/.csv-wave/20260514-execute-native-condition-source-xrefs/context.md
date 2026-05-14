# 2026-05-14 Native Condition Source Xrefs

## Goal

Continue RevDeck's native analyzer maturity by linking conditional branches to the local flag-producing comparison that explains their branch condition.

## Changes

- Added `condition_source` to `ParsedInstruction`.
- Instruction object metadata now includes `condition_source` for conditional branches when available.
- During native CFG instruction materialization, each basic block tracks the latest local flag producer:
  - `cmp`
  - `test`
- Conditional branches now reference that latest local flag producer.
- `append_instruction_xrefs` creates an instruction-level `REFERENCES` xref:
  - source: conditional branch instruction
  - target: local `cmp` / `test` instruction
- Scope is intentionally local to a basic block for this slice. Cross-block flag dataflow remains a future analysis pass.

## Tests

Added focused coverage in `crates/revdeck-index/src/lib.rs`:

- `native_conditional_branches_reference_recent_flag_producer`
  - `cmp rax,rcx` -> `je`
  - `test rax,rax` -> `jne`
  - verifies both `condition_source` metadata and `REFERENCES` xrefs

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "radare2|r2 |r2_|ImportJson|import-json|com\.revdeck\.adapters|ghidra" README.md crates tests fixtures .workflow`
  - no matches; `rg` exited with code `1`, expected for zero matches

## Native-Only Position

This iteration remains fully native. No radare2, Ghidra, adapter, import-json, or external CLI route was introduced.

## Next Candidate Slice

- Surface `condition_source` in TUI inspector / Graph Lab.
- Add cross-basic-block flag producer tracking for straight-line fallthrough.
- Add immediate forms such as `cmp r/m64, imm8/imm32` and `test r/m64, imm32`.
