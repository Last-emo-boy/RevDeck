# Execution Context: native mov rm8 register memory

## Scope

Extend native x86-64 decoder coverage for byte-sized `mov` register and memory ModRM forms.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x88` and `0x8a` byte move decoding for register and memory operands.
  - Added REX-aware byte register naming so extended and low-byte register forms keep correct operand metadata.
  - Reused shared memory operand decoding for stack/local byte slot discovery.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack-based byte memory moves, REX base forms, and REX register extension.
  - Added synthetic PE metadata coverage proving a byte stack slot records both read and write accesses.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm8_register_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_mov_rm8_register_memory_stack_slots`

Full gate is pending in this slice after the context is recorded.
