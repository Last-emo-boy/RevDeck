# Slice: native push/pop r64 registers

## Goal

Decode generic x86-64 `push r64` and `pop r64` register instructions in the native analyzer so stack prologues, epilogues, and register-save sequences expose typed operands and register access metadata.

## Changes

- Added native decode support for single-byte `0x50..0x57` `push r64` instructions.
- Added native decode support for single-byte `0x58..0x5f` `pop r64` instructions.
- Added REX.B handling for extended registers, including `push r8` and `pop r9`.
- Added typed operand roles:
  - `push r64`: source register operand
  - `pop r64`: destination register operand
- Added register access test coverage for read/write behavior.

## Current Boundary

- This slice models explicit register operands only.
- Implicit `rsp` stack pointer read/write semantics are intentionally left for a future stack-effects pass.
- Implementation remains fully native analyzer code with no external compatibility layer.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_push_pop_register_operands -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_stack_cleanup_and_epilogue_instructions -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
