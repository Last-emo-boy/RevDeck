# Wave Context: native mov r32 immediates

## Goal

Improve native instruction coverage for common 32-bit immediate loads in x86-64 code.

## Changes

- Added native decoding for `B8..BF id` as `mov r32, imm32`.
- Modeled the destination as a 32-bit register operand and the source as a 32-bit immediate operand.
- Reused the existing constant-write path so `mov eax,0x12345678` and similar forms produce register constant facts.
- Added focused coverage in the existing mov-immediate constant test.

## Verification

- `cargo test -p revdeck-index native_decoder_and_indexer_track_mov_immediate_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice keeps the analyzer native-only and improves coverage for compiler-generated code that loads constants through 32-bit GPR forms.
