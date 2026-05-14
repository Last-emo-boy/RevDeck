# Native cmovcc r32 registers

## Goal

Extend the native analyzer with register-only 32-bit conditional moves and constant selection when the prior flag-producing condition is known.

## Changes

- Added native decoding for `0f 40..4f /r` as `cmovcc r32,r32`.
- Added non-W REX.R and REX.B support for extended 32-bit registers such as `r8d` and `r9d`.
- Added constant selection for `cmovcc` when the latest `cmp` or `test` condition can be evaluated from tracked constants.
- Reused branch condition semantics for conditional move evaluation to keep condition handling consistent.
- Preserved unknown-condition behavior by avoiding speculative constant writes when the condition cannot be proven.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_cmovcc_registers -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_cmovcc_registers_select_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
