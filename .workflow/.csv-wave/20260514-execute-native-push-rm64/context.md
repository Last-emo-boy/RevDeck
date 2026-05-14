# Slice: native push r/m64

## Goal

Decode x86-64 `FF /6` stack-save instructions so `push r/m64` forms expose typed source operands and register effects.

## Changes

- Expanded the native `FF` group decoder to include `push r/m64`.
- Preserved existing `FF /2` indirect `call` and `FF /4` indirect `jmp` behavior.
- Added register operand coverage, including REX.B extended registers.
- Added memory operand coverage, including SIB addressing such as `qword ptr [rsp+0x8]`.
- `push r/m64` reuses instruction-level stack pointer effects, so metadata reports `rsp` read/write.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_push_rm64_operands -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_indirect_call_and_jump_operands -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 76 tests. The native decoder covers another common stack instruction family without introducing an external analyzer dependency.
