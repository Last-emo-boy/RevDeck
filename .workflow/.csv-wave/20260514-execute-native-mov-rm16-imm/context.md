# Native mov r/m16, imm16 Slice

## Goal

Decode operand-size-prefixed `mov r/m16, imm16` in the native x86-64 analyzer.

## Changes

- Added `0x66 C7 /0 iw` decoding.
- Added register destination support such as `ax`.
- Added memory destination support such as `word ptr [rbp-0x2]`.
- Added `read_u16` and `gpr16` helpers.
- Preserved 16-bit stack slot width metadata for immediate writes.

## Verification

- Focused decoder and synthetic PE metadata tests passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` reached 87 tests after this slice.
