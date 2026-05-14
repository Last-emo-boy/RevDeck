# Wave Context: native rex mov r32 immediates

## Goal

Extend native 32-bit immediate load coverage to REX.B extended registers.

## Changes

- Added decoding for non-W REX prefix plus `B8..BF id` as `mov r32, imm32`.
- Extended 32-bit register naming to include `r8d` through `r15d`.
- Reused the existing 32-bit immediate constant-write path for extended registers.
- Added focused coverage for `mov r8d,0x1234` and `mov r15d,0xbeef`.

## Verification

- `cargo test -p revdeck-index native_decoder_and_indexer_track_mov_immediate_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native analyzer coverage for x86-64 compiler output that loads constants into extended 32-bit registers.
