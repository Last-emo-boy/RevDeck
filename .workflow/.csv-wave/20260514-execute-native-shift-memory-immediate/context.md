# Native shift Memory-Immediate Slice

## Goal

Decode 32-bit `shl r/m32, imm8`, `shr r/m32, imm8`, and `sar r/m32, imm8` memory-destination forms in the native x86-64 analyzer.

## Changes

- Extended `c1 /4`, `c1 /5`, and `c1 /7` from register-only destinations to full `r/m32` destinations.
- Added REX prefix handling for extended 32-bit memory bases in the non-REX.W paths.
- Preserved typed memory operands with `width_bits = 32`.
- Preserved shift immediate operands with `width_bits = 8`.
- Marked memory destinations as stack slot writes for local metadata.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_shift_memory_immediates` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_shift_stack_slot_writes` passed.
- `cargo fmt --all -- --check` passed after applying `cargo fmt --all`.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 105 tests.
