# 20260514 execute native zero idioms

## Intent

Continue the native analyzer path by recognizing common register-zeroing idioms as semantic facts.

## Scope

- Decoder now recognizes `REX.W + 31 /r` and `REX.W + 33 /r` as `xor r64, r64` forms.
- The indexer recognizes `xor reg, reg` as a direct zero constant write:
  - `constant_writes: [{ register, value: 0, width_bits: 64 }]`
- Self-xor no longer contributes a stale read of the same register, so local def-use does not create a false dependency on the old register value.
- TUI Native Instruction inspector reuses the existing constants line:
  - `Constants: rax=0x0`

## Constraints

- This slice only treats identical register operands as a zero idiom.
- It does not infer constants through other arithmetic or across basic blocks.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_and_indexer_track_self_xor_zero_constants`
  - `cargo test -p revdeck-tui-tests --test tui_workspace instruction_inspector_renders_zero_idiom_constants`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`
