# Native movsx Memory-Source Slice

## Goal

Decode `movsx r32, r/m8` and `movsx r32, r/m16` memory-source forms in the native x86-64 analyzer.

## Changes

- Replaced the register-only `movsx r32, r/m8` decoder with a unified `movsx r32, r/m8|r/m16` decoder.
- Added `0f be /r` memory-source decoding for byte loads.
- Added `0f bf /r` decoding for word register and memory sources.
- Preserved REX prefix handling for extended destination registers, source registers, and memory bases.
- Preserved typed operands with `width_bits = 8` or `width_bits = 16`.
- Added stack slot read metadata for `movsx` memory-source loads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_movsx_r32_memory_sources` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_movsx_stack_slot_reads` passed.
- `cargo fmt --all -- --check` passed after applying `cargo fmt --all`.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 93 tests.
