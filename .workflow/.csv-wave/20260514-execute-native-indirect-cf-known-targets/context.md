# Native indirect control-flow known targets

## Goal

Resolve register-indirect `call` and `jmp` targets when the target register has a tracked constant value.

## Changes

- Added scan-stage resolution for indirect `call` and `jmp` register operands using tracked register constants.
- Added a lightweight pre-split target resolution pass so known indirect jump targets become basic block leaders before CFG block construction.
- Updated CFG edge generation to use parsed instruction targets after target resolution.
- Covered `mov rax,imm64; call rax` producing a function call xref and call count.
- Covered `mov r8d,imm32; jmp r8` producing a known target block, CFG edge, and instruction-to-block xref.

## Verification

- `cargo test -p revdeck-index native_indirect_call_register_uses_known_constant_target -- --nocapture`
- `cargo test -p revdeck-index native_indirect_jump_register_uses_known_constant_block_target -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
