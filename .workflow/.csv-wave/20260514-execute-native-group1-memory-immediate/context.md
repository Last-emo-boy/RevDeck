# Native group1 Memory-Immediate Slice

## Goal

Decode 32-bit group1 arithmetic and bitwise immediate instructions with memory destinations in the native x86-64 analyzer.

## Changes

- Extended `add/or/and/sub/xor r/m32, imm8/imm32` from register-only destinations to full `r/m32` destinations.
- Added REX prefix handling for extended 32-bit memory bases in the non-REX.W paths.
- Preserved typed memory operands with `width_bits = 32`.
- Marked memory destinations as stack slot writes for local metadata.
- Preserved immediate operand widths for `imm8` and `imm32`.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_group1_memory_immediates` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_group1_stack_slot_writes` passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 101 tests.
