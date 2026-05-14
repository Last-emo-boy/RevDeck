# Wave Context: native cmp r32 immediates

## Goal

Decode common 32-bit register immediate compares so native condition analysis can explain compiler-generated equality/range checks.

## Changes

- Added decoding for no-prefix `83 /7 ib` register-register form as `cmp r32, imm8`.
- Added decoding for no-prefix `81 /7 id` register-register form as `cmp r32, imm32`.
- Modeled the compared register as a 32-bit source operand.
- Added decoder coverage for:
  - `cmp eax,0x2a`
  - `cmp edx,0x12345678`
- Added analysis coverage for `mov eax,0x2a; cmp eax,0x2a; je`, proving the branch summary becomes `known taken`.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_cmp_and_test_immediate_operands -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_cmp_immediate_branches_use_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native branch explainability for common 32-bit compare patterns without adding external analyzer dependencies.
