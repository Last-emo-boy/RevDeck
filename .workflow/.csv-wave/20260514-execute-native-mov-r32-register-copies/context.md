# Wave Context: native mov r32 register copies

## Goal

Decode 32-bit register-to-register `mov` instructions natively and propagate copied constants through zero-extension aliases.

## Changes

- Added no-prefix `0x89` / `0x8b` register-register `mov r32,r32` decode.
- Added non-W REX `mov r8d..r15d,r32` and `mov r32,r8d..r15d` register-register decode.
- Preserved typed operand widths so register reads, writes, copied constants, and zero-extension aliases remain precise.
- Covered alias-fed branch outcome inference after a copied 32-bit constant.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_mov_register_copies -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_mov_register_copies_propagate_alias_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
