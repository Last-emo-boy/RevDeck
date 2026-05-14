# Native movsxd Memory-Source Slice

## Goal

Decode `movsxd r64, r/m32` memory-source forms in the native x86-64 analyzer.

## Changes

- Extended `movsxd r64, r/m32` from register-only sources to full `r/m32` sources.
- Added `48/4x 63 /r` memory-source decoding with `dword ptr` typed memory operands.
- Preserved REX prefix handling for extended destination registers and memory bases.
- Preserved typed operands with `width_bits = 32` on the source.
- Added stack slot read metadata for `movsxd` memory-source loads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_movsxd_r64_memory_sources` passed.
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_movsxd_stack_slot_reads` passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 95 tests.
