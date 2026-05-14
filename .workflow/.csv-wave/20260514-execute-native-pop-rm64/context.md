# Slice: native pop r/m64

## Goal

Decode x86-64 `8F /0` stack-restore instructions so `pop r/m64` forms expose typed destination operands and stack pointer effects.

## Changes

- Added `pop r/m64` decode for opcode `0x8f`.
- Added REX.B support for extended register destinations such as `pop r8`.
- Added memory destination support such as `pop qword ptr [rsp+0x8]`.
- Register destinations are reported as destination operands.
- Memory destinations are reported as destination memory operands; address registers remain reads.
- Reused instruction-level stack pointer effects so all `pop r/m64` forms read and write `rsp`.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_pop_rm64_operands -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_push_rm64_operands -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 77 tests. Stack restore decoding is broader and remains fully native.
