# 2026-05-14 Native CMP/TEST Typed Operands

## Goal

Continue RevDeck's native analyzer maturity by decoding condition-producing instructions into structured operands.

## Changes

- Generalized the REX.W ModRM/SIB decode path from `mov`-only to a reusable `decode_rex_w_reg_rm` helper.
- Added typed operand decode for:
  - `cmp r/m64,r64` (`0x39`)
  - `cmp r64,r/m64` (`0x3b`)
  - `test r/m64,r64` (`0x85`)
- Kept `mov r/m64,r64` and `mov r64,r/m64` behavior intact through the same helper.
- Added `RegRmInstructionSpec` with `mutates_destination` so:
  - `mov` retains destination/source semantics
  - `cmp` and `test` mark both operands as `Source`, because they only affect flags
- Preserved current DB schema and instruction metadata shape.

## Tests

Added focused coverage in `crates/revdeck-index/src/lib.rs`:

- `native_decoder_decodes_cmp_and_test_typed_operands`
  - `cmp qword ptr [rbp-0x8],r9`
  - `cmp r9,qword ptr [r12+r10*4+0x20]`
  - `test rcx,r9`

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

- Track flag-producing instruction context so conditional branches can reference their nearest `cmp`/`test`.
- Add immediate forms such as `cmp r/m64, imm8/imm32` and `test r/m64, imm32`.
- Surface `typed_operands` and condition context in TUI inspector / Graph Lab.
