# Execution Context: native cmp test rm8 register memory

## Scope

Extend native x86-64 decoder coverage for byte-sized `cmp` and `test` register and memory ModRM forms.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x38` and `0x3a` byte compare decoding for register and memory operands.
  - Added `0x84` byte test decoding for register and memory operands.
  - Shared the byte register-memory ModRM decoder path across compare and test to keep operand roles consistent.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack-based byte compare/test memory reads and REX extended byte registers.
  - Added synthetic PE metadata coverage proving byte stack compare/test operands are recorded as reads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_cmp_test_rm8_register_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_cmp_test_rm8_stack_slot_reads`

Full gate is pending in this slice after the context is recorded.
