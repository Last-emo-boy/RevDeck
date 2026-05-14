# Execution Context: native group1 adc sbb immediate

## Scope

Extend native x86-64 decoder coverage for group1 immediate `adc` and `sbb` operands.

## Changes

- `crates/revdeck-index/src/native_decode.rs`
  - Added `0x80 /2,/3` byte `adc` and `sbb` decoding for register and memory destinations.
  - Added `0x81 /2,/3` and `0x83 /2,/3` 32-bit `adc` and `sbb` decoding for register and memory destinations.

- `crates/revdeck-index/src/lib.rs`
  - Added decoder coverage for register, stack memory, REX base memory, and real low-byte register forms.
  - Added synthetic PE metadata coverage proving byte and 32-bit stack operands are recorded as writes.
  - Added in-place register access coverage for `adc` and `sbb` while keeping constant folding out of this slice because carry flag state is not modeled here.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_group1_adc_sbb_immediates`
- `cargo test -p revdeck-index native_decoder_decodes_group1_rm8_adc_sbb_immediates`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_group1_adc_sbb_stack_slot_writes`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_group1_rm8_adc_sbb_stack_slot_writes`
- `cargo test -p revdeck-index native_32_bit_add_sub_immediates_fold_known_constants`

Full gate completed after context recording:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- native-only audit
