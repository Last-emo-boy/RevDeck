# Execution Context: native cmovcc rm32 memory

## Scope

Extend native x86-64 decoder coverage for conditional moves that read 32-bit memory operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0f 40..4f /r` `cmovcc r32,r/m32` decoding for memory sources.
  - Preserved register source decoding and REX register/base extension behavior.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack memory and REX base memory sources.
  - Added synthetic PE metadata coverage proving stack memory `cmovcc` operands are recorded as reads.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_cmovcc_memory_sources`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_cmovcc_stack_slot_reads`
- `cargo test -p revdeck-index native_32_bit_cmovcc_registers_select_known_constants`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
