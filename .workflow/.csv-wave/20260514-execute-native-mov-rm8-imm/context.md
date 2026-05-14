# Slice: native mov r/m8 immediate

## Goal

Decode byte immediate stores so local byte flags, chars, and boolean initializers are visible in native metadata.

## Changes

- Added `C6 /0` decoding for `mov r/m8, imm8`.
- Added register destination support, including REX.B byte registers such as `r8b`.
- Added memory destination support such as `mov byte ptr [rbp-0x1],0x1`.
- Immediate operands are typed as 8-bit source operands.
- Stack slot metadata now records byte-width immediate writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm8_immediate_destinations -- --nocapture`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_byte_stack_slot_immediate_writes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 85 tests. Native stack slot coverage now includes byte-sized immediate writes without using any external analyzer.
