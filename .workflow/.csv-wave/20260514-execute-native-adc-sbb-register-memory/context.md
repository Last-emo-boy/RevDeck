# Execution Context: native adc sbb register memory

## Scope

Extend native x86-64 decoder coverage for `adc` and `sbb` register-memory opcode forms.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x10/0x12` byte `adc r/m8,r8` and `adc r8,r/m8` decoding.
  - Added `0x18/0x1a` byte `sbb r/m8,r8` and `sbb r8,r/m8` decoding.
  - Added `0x11/0x13` 32-bit `adc r/m32,r32` and `adc r32,r/m32` decoding.
  - Added `0x19/0x1b` 32-bit `sbb r/m32,r32` and `sbb r32,r/m32` decoding.
  - Routed `REX.W` `adc` and `sbb` register-memory forms through the native 64-bit decoder path.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for register, stack memory, REX base memory, REX byte register, and REX.W memory forms.
  - Added synthetic PE metadata coverage proving byte and 32-bit stack operands are recorded as read/write stack slots.
  - Extended in-place arithmetic register read tracking so register and memory source forms read the previous destination value, while preserving the self-xor zeroing exception.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_adc_sbb_rm8_register_memory_operands`
- `cargo test -p revdeck-index native_decoder_decodes_32_bit_adc_sbb_register_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_adc_sbb_register_memory_stack_slot_writes`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_adc_sbb_rm8_register_memory_stack_slot_writes`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
