# Native inc/dec Memory-Destination Slice

## Goal

Decode 32-bit `inc r/m32` and `dec r/m32` memory-destination forms in the native x86-64 analyzer.

## Changes

- Extended `ff /0` and `ff /1` from register-only destinations to full `r/m32` destinations.
- Preserved REX prefix handling for extended 32-bit memory bases in the non-REX.W paths.
- Preserved typed memory operands with `width_bits = 32`.
- Marked memory destinations as stack slot writes for local metadata.
- Kept other `ff` group forms routed through their existing call, jump, and push paths.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_inc_dec_memory_operands` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_inc_dec_stack_slot_writes` passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 103 tests.
