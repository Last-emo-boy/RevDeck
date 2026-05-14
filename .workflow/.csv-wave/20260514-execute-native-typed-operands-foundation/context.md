# 2026-05-14 Native Typed Operands Foundation

## Goal

Advance RevDeck's native analyzer toward a richer disassembly model without adding any external analyzer compatibility path.

## Changes

- Added crate-private typed operand structures in `crates/revdeck-index/src/native_decode.rs`:
  - `DecodedOperand`
  - `OperandRole`
  - `OperandKind`
- Kept existing `DecodedInstruction.operands` text output stable for DB compatibility.
- Added typed operands for:
  - direct relative call/jump/jcc targets
  - RIP-relative indirect call/jump import slots
  - RIP-relative `lea`/`mov` data references
- Added `RipRelativeSpec` to keep opcode definitions compact and clippy-clean.
- Persisted typed operands into instruction object `metadata_json` under `typed_operands`.
- Updated xref construction in `crates/revdeck-index/src/lib.rs` to prefer structured operand targets while preserving legacy `target` and `data_target` fallback behavior.
- Extended focused tests for:
  - relative call typed targets
  - RIP-relative memory operand role/kind/base/displacement/width
  - string reference xrefs
  - indirect IAT calls
  - IAT jump thunks

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

- Add typed operand coverage for more x86-64 ModRM/SIB memory forms.
- Move x86 opcode families into a dedicated `native_decode::x86` submodule.
- Add TUI Graph Lab detail rendering for `typed_operands` and import-slot references.
