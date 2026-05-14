# Execution Context: native shift rm8 one cl

## Scope

Extend native x86-64 decoder coverage for byte-sized shift operands whose count is encoded implicitly as one or dynamically through `cl`.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0xd0 /4,/5,/7` byte `shl`, `shr`, and `sar` decoding for register and memory destinations with an implicit `0x1` count.
  - Added `0xd2 /4,/5,/7` byte `shl`, `shr`, and `sar` decoding for register and memory destinations with `cl` as the count source.
  - Kept existing `0xc0` immediate-count decoding on the same byte shift helper.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for stack memory, REX base memory, and real low-byte register forms.
  - Added synthetic PE metadata coverage proving byte shift stack operands are recorded as writes for implicit-one and `cl` counts.
  - Updated in-place register access detection so dynamic shift counts still mark the destination register as read before write.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_shift_rm8_one_and_cl_counts`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_shift_rm8_one_and_cl_stack_slot_writes`
- `cargo test -p revdeck-index native_decoder_decodes_shift_rm8_memory_immediates`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
