# Wave Context: native test r32 registers

## Goal

Decode common 32-bit register `test` instructions so native condition analysis can explain compiler-generated zero checks.

## Changes

- Added decoding for no-prefix `0x85 /r` register-register forms as `test r/m32,r32`.
- Modeled both operands as 32-bit source registers.
- Added focused decoder coverage for:
  - `test eax,eax`
  - `test ecx,edx`
- Added focused analysis coverage for `mov eax,0; test eax,eax; je`, proving the branch summary becomes `known taken`.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_test_register_operands -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_test_self_branches_use_known_zero_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native branch explainability for frequent x86-64 compiler patterns without changing external dependencies.
