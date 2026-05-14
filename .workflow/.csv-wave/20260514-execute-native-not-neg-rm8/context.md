# Execution Context: native not neg rm8

## Scope

Extend native x86-64 decoder coverage for byte-sized unary bitwise and arithmetic operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xf6 /2` and `0xf6 /3` byte `not` and `neg` decoding for register and memory operands.
  - Preserved existing `0xf6 /0` byte test immediate decoding by trying unary forms first and falling back to test.
  - Relaxed the `0xf6` top-level length guard so register-only forms with a real REX prefix decode correctly.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for byte stack memory not/neg, REX base forms, and real `0x40` low-byte registers.
  - Added synthetic PE metadata coverage proving byte not/neg stack operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_not_neg_rm8_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_not_neg_rm8_stack_slot_writes`
- `cargo test -p revdeck-index native_decoder_decodes_cmp_test_rm8_immediate_operands`

Full gate is pending in this slice after the context is recorded.

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
