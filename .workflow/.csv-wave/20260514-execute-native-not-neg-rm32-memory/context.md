# Execution Context: native not neg rm32 memory

## Scope

Extend native x86-64 decoder coverage for 32-bit unary arithmetic and bitwise memory destinations.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xf7 /2` and `0xf7 /3` `not` and `neg` decoding for `r/m32` memory operands.
  - Kept register decoding intact and allowed REX base extension for memory operands.
  - Preserved existing `0xf7 /0` test immediate fallback behavior.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack memory and REX base memory forms.
  - Added synthetic PE metadata coverage proving 32-bit stack memory `not` and `neg` operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_not_neg_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_not_neg_stack_slot_writes`
- `cargo test -p revdeck-index native_decoder_decodes_32_bit_cmp_and_test_memory_immediates`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
