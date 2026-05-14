# Wave Context: native add/sub r32 immediates

## Goal

Decode register-only 32-bit `add` / `sub` immediate instructions natively and fold known constants through arithmetic updates.

## Changes

- Added no-prefix `0x81` / `0x83` register-only group-1 decode for:
  - `add r32,imm8`
  - `add r32,imm32`
  - `sub r32,imm8`
  - `sub r32,imm32`
- Added non-W REX register-only support for extended registers such as `r8d` and `r9d`.
- Treated in-place arithmetic destinations as both register reads and writes.
- Folded known constants through 32-bit `add` / `sub` operations.
- Propagated folded 32-bit results through existing zero-extension alias analysis into branch outcome summaries.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_add_sub_immediates -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_add_sub_immediates_fold_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
