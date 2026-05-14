# Native mov r/m16, r16 Slice

## Goal

Decode operand-size-prefixed `mov r/m16, r16` and `mov r16, r/m16` in the native x86-64 analyzer.

## Changes

- Added `0x66 89 /r` decoding for 16-bit register-to-register and register-to-memory moves.
- Added `0x66 8b /r` decoding for 16-bit memory-to-register and register-to-register moves.
- Added REX prefix handling for extended 16-bit registers such as `r8w`.
- Extended 16-bit register aliases from the legacy 8 registers to `r8w` through `r15w`.
- Preserved typed operands with `width_bits = 16` for registers and memory.
- Preserved stack slot read/write metadata for 16-bit stack locals.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm16_register_and_memory_forms` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_word_stack_slot_register_moves` passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 89 tests.
