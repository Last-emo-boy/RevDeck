# Wave Context: native cmp r32 registers

## Goal

Decode common 32-bit register-register compares so native condition analysis can explain equality checks between 32-bit GPR values.

## Changes

- Added decoding for no-prefix `39 /r` register-register forms as `cmp r/m32,r32`.
- Added decoding for no-prefix `3b /r` register-register forms as `cmp r32,r/m32`.
- Modeled both operands as 32-bit source registers.
- Added decoder coverage for:
  - `cmp eax,ecx`
  - `cmp ebx,eax`
- Added analysis coverage for `mov eax,0x2a; mov ecx,0x2a; cmp eax,ecx; je`, proving the branch summary becomes `known taken`.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_cmp_and_test_typed_operands -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_cmp_register_branches_use_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native branch explainability for common 32-bit register compare patterns without adding external analyzer dependencies.
