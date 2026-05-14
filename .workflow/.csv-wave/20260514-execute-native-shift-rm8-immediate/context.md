# Execution Context: native shift rm8 immediate

## Scope

Extend native x86-64 decoder coverage for byte-sized shift immediate operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xc0 /4`, `0xc0 /5`, and `0xc0 /7` byte shift immediate decoding for `shl`, `shr`, and `sar`.
  - Added REX-aware handling so real `0x40` low-byte register forms keep correct register names.
  - Reused shared memory operand decoding so byte stack/local metadata keeps consistent base, displacement, and width fields.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for byte stack memory shifts, REX base forms, and real `0x40` low-byte registers.
  - Added synthetic PE metadata coverage proving byte shift stack operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_shift_rm8_memory_immediates`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_shift_rm8_stack_slot_writes`

Full gate is pending in this slice after the context is recorded.
