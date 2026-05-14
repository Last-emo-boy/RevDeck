# Native movsxd r64,r32 sign extension

## Goal

Extend the native analyzer with register-only 32-bit to 64-bit sign extension.

## Changes

- Added REX.W native decoding for `63 /r` as `movsxd r64,r32`.
- Added REX.R and REX.B support for extended registers such as `r9,r8d`.
- Added constant folding for `movsxd` by sign-extending tracked 32-bit source constants into 64-bit destination constants.
- Added focused coverage for negative and positive sign extension cases.
- Updated the REX.W dispatch path so `0x63` reaches native decoding instead of the generic unknown-byte fallback.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_movsxd_r64_rm32_registers -- --nocapture`
- `cargo test -p revdeck-index native_movsxd_r64_rm32_sign_extends_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
