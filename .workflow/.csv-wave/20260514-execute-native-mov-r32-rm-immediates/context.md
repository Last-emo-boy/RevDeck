# Wave Context: native mov r32 rm immediates

## Goal

Decode register-only `c7 /0 id` 32-bit `mov` instructions natively and feed their constants into existing zero-extension alias analysis.

## Changes

- Added no-prefix register-only `mov r32,imm32` decode for `0xc7 /0 id`.
- Added non-W REX register-only support for `mov r8d..r15d,imm32`.
- Preserved destination and immediate operand widths as 32-bit typed operands.
- Reused existing native `mov` immediate constant writes and zero-extension alias propagation.
- Covered branch outcome inference from `mov edx,0x2a; cmp rdx,0x2a; je`.

## Verification

- `cargo test -p revdeck-index native_decoder_and_indexer_track_mov_immediate_constants -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_mov_rm_immediates_propagate_alias_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
