# Execution Context: native cmp test rm8 immediate

## Scope

Extend native x86-64 decoder coverage for byte-sized immediate compare and test operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x80 /7` byte compare immediate decoding for register and memory operands.
  - Added `0xf6 /0` byte test immediate decoding for register and memory operands.
  - Split real REX prefix presence from the default no-prefix state so `0x40` low-byte register names are decoded correctly.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for byte stack memory compare/test immediate operands, REX base forms, and real `0x40` low-byte registers.
  - Added synthetic PE metadata coverage proving byte immediate compare/test stack operands are recorded as reads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_cmp_test_rm8_immediate_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_cmp_test_rm8_immediate_stack_slot_reads`

Full gate is pending in this slice after the context is recorded.
