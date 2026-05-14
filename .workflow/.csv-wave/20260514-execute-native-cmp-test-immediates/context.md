# 20260514 execute native cmp/test immediates

## Intent

Continue RevDeck native analyzer iteration without external reverse engineering dependencies. This slice expands typed operand coverage for common flag-producing x86-64 instructions so conditional branch source tracking works for immediate comparisons.

## Scope

- Added `OperandKind::Immediate` for serialized native instruction operands.
- Added REX.W immediate forms:
  - `81 /7 id`: `cmp r/m64, imm32`
  - `83 /7 ib`: `cmp r/m64, imm8`
  - `f7 /0 id`: `test r/m64, imm32`
- Immediate forms use existing ModRM/SIB memory decoding and REX.B register extension.
- `cmp` and `test` immediate operands are both modeled as `OperandRole::Source`; the instructions produce flags and do not mutate the compared operand.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_decodes_cmp_and_test_immediate_operands`
  - `cargo test -p revdeck-index native_conditional_branch_references_immediate_flag_producer`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`

