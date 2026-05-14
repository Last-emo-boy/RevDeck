# Slice: native mov r/m32 immediate memory destinations

## Goal

Decode `mov r/m32, imm32` memory destination forms so local variable initialization and stack slot writes are visible to the native analyzer.

## Changes

- Extended the existing `C7 /0` decoder beyond register-only destinations.
- Added memory destination support for forms such as `mov dword ptr [rbp-0x4],0x2a`.
- Added REX.B memory base support for forms such as `mov dword ptr [r8+0x10],0xbeef`.
- Kept register destination behavior unchanged.
- Stack slot metadata now captures immediate writes to frame-relative memory.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_mov_rm32_immediate_memory_destinations -- --nocapture`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_tracks_stack_slot_immediate_writes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 79 tests. Stack local initialization is represented in native function metadata without introducing an external analyzer dependency.
