# Execution Context: native shift rm32 one cl

## Scope

Extend native x86-64 decoder coverage for 32-bit shift operands whose count is encoded implicitly as one or dynamically through `cl`.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xd1 /4,/5,/7` `shl`, `shr`, and `sar` decoding for `r/m32` register and memory destinations with an implicit `0x1` count.
  - Added `0xd3 /4,/5,/7` `shl`, `shr`, and `sar` decoding for `r/m32` register and memory destinations with `cl` as the count source.
  - Kept existing `0xc1` immediate-count decoding on the same 32-bit shift helper.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for register, stack memory, and REX base memory forms.
  - Added synthetic PE metadata coverage proving 32-bit stack shift operands are recorded as writes for implicit-one and `cl` counts.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_shift_one_and_cl_counts`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_shift_one_and_cl_stack_slot_writes`
- `cargo test -p revdeck-index native_decoder_decodes_32_bit_shift_memory_immediates`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
