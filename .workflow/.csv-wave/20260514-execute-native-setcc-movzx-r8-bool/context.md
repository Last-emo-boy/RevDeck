# Native setcc/movzx r8 boolean propagation

## Goal

Extend the native analyzer with common compiler booleanization support: `setcc r8` followed by `movzx r32,r8`.

## Changes

- Added native register-only decoding for `0f 90..9f /r` as `setcc r8`.
- Added native register-only decoding for `0f b6 /r` as `movzx r32,r8`.
- Added low-byte register names for traditional and REX-extended byte registers.
- Added constant writes for `setcc` when the latest `cmp` or `test` condition can be evaluated.
- Added `movzx` constant propagation from tracked byte-register constants into 32-bit destination registers.
- Covered both `sete al; movzx eax,al` and REX extended `setne r8b; movzx r9d,r8b` flows.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_setcc_and_movzx_r32_rm8_registers -- --nocapture`
- `cargo test -p revdeck-index native_setcc_and_movzx_fold_known_boolean_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
