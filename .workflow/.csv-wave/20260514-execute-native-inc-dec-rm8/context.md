# Execution Context: native inc dec rm8

## Scope

Extend native x86-64 decoder coverage for byte-sized increment and decrement operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xfe /0` and `0xfe /1` byte increment/decrement decoding for register and memory operands.
  - Added REX-aware handling so real `0x40` low-byte register forms keep correct register names.
  - Reused shared memory operand decoding so byte stack/local metadata keeps consistent base, displacement, and width fields.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for byte stack memory inc/dec, REX base forms, and real `0x40` low-byte registers.
  - Added synthetic PE metadata coverage proving byte inc/dec stack operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_inc_dec_rm8_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_inc_dec_rm8_stack_slot_writes`

Full gate is pending in this slice after the context is recorded.
