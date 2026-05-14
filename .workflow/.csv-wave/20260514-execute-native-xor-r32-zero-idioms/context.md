# Wave Context: native xor r32 zero idioms

## Goal

Decode 32-bit xor zero idioms natively and feed zero-extension alias analysis without any external analyzer dependency.

## Changes

- Added no-prefix `0x31` / `0x33` register-register `xor r32,r32` decode.
- Added non-W REX `xor r8d..r15d,r8d..r15d` decode.
- Made self-xor zero constant writes use the destination operand width instead of assuming 64-bit writes.
- Propagated 32-bit self-xor zero constants through zero-extended 64-bit register aliases.
- Covered alias-fed branch outcome inference such as `xor eax,eax; test rax,rax; je`.

## Verification

- `cargo test -p revdeck-index native_decoder_and_indexer_track_self_xor_zero_constants -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_xor_zero_aliases_feed_64_bit_conditions -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit over `README.md crates tests fixtures .workflow`: exit code 1, no external compatibility patterns found.
