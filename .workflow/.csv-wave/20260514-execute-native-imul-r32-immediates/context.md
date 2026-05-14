# Native imul r32 immediates

## Goal

Extend the native analyzer with register-only 32-bit three-operand `imul` immediate decoding and constant folding.

## Changes

- Added native decoding for `6b /r ib` and `69 /r id` as `imul r32,r32,imm`.
- Added non-W REX.R and REX.B support for extended 32-bit registers such as `r8d` and `r9d`.
- Added register access coverage where the destination is written and the source register is read.
- Added constant folding for `imul` from a known source register and immediate operand into the destination register.
- Preserved 32-bit zero-extension alias propagation through existing constant write tracking.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_imul_immediates -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_imul_immediates_fold_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
