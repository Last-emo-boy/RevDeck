# Wave Context: native bitwise r32 immediates

## Goal

Decode register-only 32-bit bitwise immediate instructions natively and fold known constants through bitmask updates.

## Changes

- Generalized 32-bit group-1 immediate decode for register-only operands.
- Added native decode for:
  - `and r32,imm8`
  - `and r32,imm32`
  - `or r32,imm8`
  - `or r32,imm32`
  - `xor r32,imm8`
  - `xor r32,imm32`
- Added non-W REX register-only support for extended registers such as `r8d`.
- Extended in-place arithmetic read/write tracking to immediate bitwise operations without regressing self-xor zero idioms.
- Folded known constants through `and` / `or` / `xor` operations and propagated folded 32-bit results through zero-extension aliases.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_group1_immediates -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_bitwise_immediates_fold_known_constants -- --nocapture`
- `cargo test -p revdeck-index native_decoder_and_indexer_track_self_xor_zero_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
