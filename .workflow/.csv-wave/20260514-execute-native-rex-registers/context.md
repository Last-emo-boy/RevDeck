# 2026-05-14 Native REX Register Extension

## Goal

Continue RevDeck's native x86-64 decoder maturity by decoding REX.R/X/B register extensions for typed operands.

## Changes

- Expanded the REX.W `mov` decoder entry from fixed `0x48` to `0x48..=0x4f`.
- Added `RexPrefix` parsing for:
  - `REX.R` register operand extension
  - `REX.X` SIB index extension
  - `REX.B` ModRM/SIB base extension
- Extended `gpr64` from low 8 GPRs to all 16 x86-64 GPRs:
  - `rax`-`rdi`
  - `r8`-`r15`
- Preserved current operand metadata shape and DB schema.

## Tests

Added focused coverage in `crates/revdeck-index/src/lib.rs`:

- `native_decoder_decodes_rex_extended_registers`
  - `mov r9,qword ptr [rsp+r10*4+0x10]`
  - `mov qword ptr [r12-0x10],rcx`

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

- Add typed operands for `cmp`, `test`, arithmetic, and stack-memory idioms.
- Add operand-size variants and non-REX 32-bit register naming.
- Surface `typed_operands` in TUI inspector / Graph Lab details.
