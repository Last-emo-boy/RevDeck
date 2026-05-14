# Execution Context: native setcc rm8 memory

## Scope

Extend native x86-64 decoder coverage for conditional byte writes to memory.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0f 90..9f /r` `setcc` decoding for `r/m8` memory destinations.
  - Preserved register destination decoding, including real REX low-byte register handling.
  - Allowed REX base extension for byte memory destinations.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack memory, REX base memory, and real low-byte register forms.
  - Added synthetic PE metadata coverage proving stack byte `setcc` operands are recorded as writes.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_setcc_rm8_memory_operands`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_setcc_stack_slot_writes`
- `cargo test -p revdeck-index native_decoder_decodes_setcc_and_movzx_r32_rm8_registers`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
