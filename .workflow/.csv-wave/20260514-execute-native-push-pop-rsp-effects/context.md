# Slice: native push/pop rsp effects

## Goal

Expose the implicit stack pointer effects of x86-64 `push` and `pop` instructions in the native analyzer's register access summaries.

## Changes

- Added instruction-level stack pointer effect detection for `push` and `pop`.
- `push r64` now reports reads from the source register and `rsp`, and writes to `rsp`.
- `pop r64` now reports a read from `rsp`, and writes to the destination register and `rsp`.
- Kept typed operands focused on explicit instruction operands; the implicit `rsp` effect is represented in instruction metadata instead.
- Added a helper to insert derived register accesses in sorted, deduplicated order.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_push_pop_register_operands -- --nocapture`
- `cargo test -p revdeck-index synthetic_pe_instruction_metadata_tracks_push_pop_stack_pointer_effects -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 72 tests, and stack-save / stack-restore sequences expose stronger dataflow metadata without introducing an external analyzer dependency.
