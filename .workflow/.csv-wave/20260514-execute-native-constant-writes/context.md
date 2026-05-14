# 20260514 execute native constant writes

## Intent

Continue the native analyzer path by recording direct register constants produced by decoded instructions.

## Scope

- Decoder now recognizes:
  - `REX.W + B8..BF imm64` as `mov r64, imm64`
  - `REX.W + C7 /0 imm32` as `mov r/m64, imm32`
- Instruction metadata now includes:
  - `constant_writes`
- The indexer records direct `mov` destination-register/source-immediate pairs as register constant write facts.
- TUI Native Instruction inspector renders:
  - `Constants: rax=0x2a`

## Constraints

- This slice records direct write facts only. It does not perform constant propagation or cross-block value analysis yet.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_and_indexer_track_mov_immediate_constants`
  - `cargo test -p revdeck-tui-tests --test tui_workspace instruction_inspector_renders_constant_writes`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`
