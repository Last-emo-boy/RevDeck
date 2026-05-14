# Wave Context: native test r32 immediates

## Goal

Decode 32-bit register-immediate `test` instructions natively and use them for bitmask and parity branch outcome summaries.

## Changes

- Added no-prefix `0xf7 /0 id` register-only `test r32,imm32` decode.
- Preserved typed operand widths for the tested register and immediate.
- Extended existing native branch summaries to cover 32-bit immediate bitmask checks through the common `test` condition path.
- Covered known `je` bitmask and `jp` parity outcomes for 32-bit operands.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_cmp_and_test_immediate_operands -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_test_immediate_branches_summarize_known_outcomes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
