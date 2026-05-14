# Wave Context: native shift r32 immediates

## Goal

Decode register-only 32-bit `shl` / `shr` immediate instructions natively and fold known constants through bit-shift updates.

## Changes

- Added no-prefix `0xc1 /4 ib` register-only `shl r32,imm8` decode.
- Added no-prefix `0xc1 /5 ib` register-only `shr r32,imm8` decode.
- Added non-W REX register-only support for extended registers such as `r8d` and `r9d`.
- Extended in-place read/write tracking to `shl` / `shr`.
- Folded known constants through 32-bit logical shift operations and propagated folded results through zero-extension aliases.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_shift_immediates -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_shift_immediates_fold_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
