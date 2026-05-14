# Execution Context: native group1 rm8 immediate

## Scope

Extend native x86-64 decoder coverage for byte-sized group1 immediate arithmetic and bitwise operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x80` byte group1 immediate decoding for `add`, `or`, `and`, `sub`, and `xor`.
  - Preserved existing byte compare immediate decoding by trying the group1 mutating forms first and falling back to compare.
  - Reused shared memory operand decoding so byte stack/local metadata keeps consistent base, displacement, and width fields.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for byte stack memory group1 writes, REX base forms, and real `0x40` low-byte registers.
  - Added synthetic PE metadata coverage proving byte group1 stack operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_group1_rm8_immediates`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_group1_rm8_stack_slot_writes`

Full gate is pending in this slice after the context is recorded.
