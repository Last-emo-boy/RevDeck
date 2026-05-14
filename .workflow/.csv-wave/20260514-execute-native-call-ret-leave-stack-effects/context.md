# Slice: native call/ret/leave stack effects

## Goal

Expose implicit register effects for stack-control instructions in native instruction metadata.

## Changes

- `call` now reports `rsp` as read and written.
- `ret` now reports `rsp` as read and written.
- `leave` now reports `rbp` as read, and `rbp` / `rsp` as written.
- Reused the same sorted, deduplicated register insertion helper used by `push` / `pop` stack effects.
- Kept typed operands scoped to explicit operands while recording implicit effects in instruction metadata.

## Verification

- `cargo test -p revdeck-index native_decoder_tracks_call_return_stack_pointer_effects -- --nocapture`
- `cargo test -p revdeck-index synthetic_pe_instruction_metadata_tracks_call_return_stack_effects -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_stack_cleanup_and_epilogue_instructions -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 74 tests. Stack-oriented control-flow instructions produce richer register metadata for def-use, TUI inspection, and future stack discipline analysis without relying on any external analyzer.
