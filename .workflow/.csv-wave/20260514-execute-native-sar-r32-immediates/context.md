# Wave Context: native sar r32 immediates

## Goal

Decode register-only 32-bit `sar` immediate instructions natively and fold signed arithmetic shift results into branch reasoning.

## Changes

- Added no-prefix `0xc1 /7 ib` register-only `sar r32,imm8` decode.
- Added non-W REX register-only support for extended registers such as `r8d`.
- Extended in-place read/write tracking to `sar`.
- Added signed arithmetic right shift constant folding with 32-bit sign preservation.
- Propagated folded signed values into existing `test` and `js` condition summaries.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_shift_immediates -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_sar_immediates_fold_signed_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
