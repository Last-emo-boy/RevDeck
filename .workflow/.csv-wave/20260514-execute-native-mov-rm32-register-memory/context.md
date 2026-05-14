# Execution Context: native mov rm32 register memory

## Scope

Extend the native x86-64 decoder coverage for 32-bit `mov` register and memory ModRM forms.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Allowed `0x89` and `0x8b` rm32/r32 decoding to handle memory ModRM forms.
  - Preserved the dedicated RIP-relative data-reference path by excluding that addressing pattern from the generic non-prefix path.
  - Reused `decode_memory_operand` so stack-slot metadata receives base, displacement, effective address, and width fields consistently.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack-based and REX-base 32-bit memory moves.
  - Added synthetic PE metadata coverage proving a 32-bit stack slot records both read and write accesses.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm32_register_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_mov_rm32_register_memory_stack_slots`

Full gate is pending in this slice after the context is recorded.
