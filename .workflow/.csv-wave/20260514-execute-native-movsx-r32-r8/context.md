# Native movsx r32,r8 sign extension

## Goal

Extend the native analyzer with register-only byte-to-32-bit sign extension and low-byte constant alias propagation.

## Changes

- Added native register-only decoding for `0f be /r` as `movsx r32,r8`.
- Added non-W REX.R and REX.B support for extended byte registers such as `r8b`.
- Added constant folding for `movsx` from tracked byte-register constants into 32-bit destination registers.
- Added low-byte alias constant tracking from 32-bit and 64-bit register writes, enabling flows such as `mov eax,0x80; movsx ecx,al`.
- Kept alias propagation one-way from wider writes to low-byte constants to avoid inventing full partial-register semantics.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_movsx_r32_rm8_registers -- --nocapture`
- `cargo test -p revdeck-index native_movsx_r32_rm8_sign_extends_known_constants -- --nocapture`
- `cargo test -p revdeck-index native_setcc_and_movzx_fold_known_boolean_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
