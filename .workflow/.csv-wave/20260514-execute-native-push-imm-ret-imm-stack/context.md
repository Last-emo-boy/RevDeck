# Slice: native push imm and ret imm stack coverage

## Goal

Cover common stack-related immediate forms in the native decoder so calling convention and stack cleanup patterns are represented with typed operands and register effects.

## Changes

- Added `push imm8` decode for opcode `0x6a`.
- Added `push imm32` decode for opcode `0x68`.
- Added `ret imm16` decode for opcode `0xc2`.
- Immediate operands are typed as source operands with their encoded widths.
- Existing instruction-level stack pointer effects now apply to these forms:
  - `push imm*`: reads and writes `rsp`
  - `ret imm16`: reads and writes `rsp`

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_push_immediates_and_ret_stack_cleanup -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 75 tests. The native analyzer covers more stack setup and cleanup encodings while preserving the native-only architecture boundary.
