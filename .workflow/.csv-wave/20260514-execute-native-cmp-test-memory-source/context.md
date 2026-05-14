# Native cmp/test Memory-Source Slice

## Goal

Decode 32-bit `cmp` and `test` memory-source forms in the native x86-64 analyzer.

## Changes

- Extended `cmp r/m32, r32` and `cmp r32, r/m32` from register-only sources to full `r/m32` operands.
- Extended `test r/m32, r32` from register-only sources to full `r/m32` operands.
- Added REX prefix handling for extended 32-bit registers and memory bases in the non-REX.W paths.
- Preserved typed memory operands with `width_bits = 32`.
- Added stack slot read metadata for `cmp` and `test` memory-source reads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_cmp_and_test_memory_operands` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_cmp_test_stack_slot_reads` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_movsxd_stack_slot_reads` passed after correcting an adjacent fixture length.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 97 tests.
