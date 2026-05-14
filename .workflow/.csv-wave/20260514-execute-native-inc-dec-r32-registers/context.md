# Wave Context: native inc/dec r32 registers

## Goal

Decode register-only 32-bit `inc` / `dec` instructions natively and fold known constants through single-step loop counter updates.

## Changes

- Added no-prefix `0xff /0` register-only `inc r32` decode.
- Added no-prefix `0xff /1` register-only `dec r32` decode.
- Added non-W REX register-only support for extended registers such as `r8d` and `r9d`.
- Extended in-place read/write tracking to `inc` / `dec`.
- Folded known constants through `inc` / `dec` and propagated folded 32-bit results through zero-extension aliases.
- Preserved existing REX.W `ff` indirect call/jump behavior after the new non-W REX path.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_inc_dec_registers -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_inc_dec_registers_fold_known_constants -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_indirect_call_and_jump_operands -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
