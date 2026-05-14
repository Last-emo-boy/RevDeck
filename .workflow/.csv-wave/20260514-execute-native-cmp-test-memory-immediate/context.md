# Native cmp/test Memory-Immediate Slice

## Goal

Decode 32-bit `cmp r/m32, imm` and `test r/m32, imm32` memory-source forms in the native x86-64 analyzer.

## Changes

- Extended `cmp r/m32, imm8/imm32` from register-only operands to full `r/m32` operands.
- Extended `test r/m32, imm32` from register-only operands to full `r/m32` operands.
- Added REX prefix handling for extended 32-bit memory bases in the non-REX.W paths.
- Preserved typed memory operands with `width_bits = 32` and immediate operand widths.
- Added stack slot read metadata for `cmp` and `test` memory-immediate reads.
- Preserved existing register `not`/`neg` handling by keeping the register-form `f7` path ahead of the memory-immediate fallback.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_cmp_and_test_memory_immediates` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_cmp_test_immediate_stack_slot_reads` passed.
- `cargo fmt --all -- --check` passed after applying `cargo fmt --all`.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 99 tests.
