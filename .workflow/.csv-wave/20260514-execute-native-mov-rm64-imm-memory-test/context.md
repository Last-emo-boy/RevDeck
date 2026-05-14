# Slice: native mov r/m64 immediate memory coverage

## Goal

Lock down native decoder behavior for `REX.W + C7 /0` memory destinations so 64-bit stack local immediate writes remain covered by tests.

## Changes

- Added direct coverage for `mov qword ptr [rbp-0x8], imm32`.
- Verified immediate sign extension in the operand value and rendered operand text.
- Verified memory destination metadata:
  - destination role
  - memory kind
  - `rbp` base
  - negative displacement
  - 64-bit memory width
- Confirmed register access summaries treat the memory base as a read and do not report a register write for memory stores.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm64_sign_extended_immediate_memory_destinations -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 80 tests. Existing native `mov r/m64, imm32` behavior has explicit regression coverage.
