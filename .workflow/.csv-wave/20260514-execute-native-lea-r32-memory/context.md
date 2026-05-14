# Slice: native lea r32 memory operands

## Goal

Decode general `lea r32, m` forms so 32-bit address calculations and stack address references are visible in native metadata.

## Changes

- Generalized the `lea` decoder to support both 32-bit and 64-bit destination widths.
- Added bare `0x8d` support for `lea r32,m`.
- Added non-W REX prefix support for extended 32-bit destination and address registers.
- Covered examples:
  - `lea eax,[rbp-0x10]`
  - `lea r9d,[rsp+r10*4+0x20]`
- Preserved RIP-relative `lea` constant propagation.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_lea_r32_memory_operands -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_lea_r64_memory_operands -- --nocapture`
- `cargo test -p revdeck-index native_indexer_tracks_lea_data_target_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 83 tests. Address calculation coverage is broader while remaining native-only.
