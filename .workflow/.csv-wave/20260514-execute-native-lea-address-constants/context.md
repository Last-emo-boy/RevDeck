# 20260514 execute native lea address constants

## Intent

Continue the native analyzer path by treating RIP-relative `lea` as a direct register constant-address write.

## Scope

- `constant_writes` now accepts instruction `data_target` context.
- `lea reg,[rip+disp32]` records the resolved target address as a register constant write.
- RIP-relative `mov reg,[rip+disp32]` remains a memory load and does not become a constant write.
- RIP-relative destination register operands now carry width metadata.
- TUI Native Instruction inspector shows both:
  - `Data target: ...`
  - `Constants: rcx=0x...`

## Constraints

- This slice handles direct RIP-relative `lea` only.
- It does not implement full constant propagation or cross-block value flow.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_indexer_tracks_lea_data_target_constants`
  - `cargo test -p revdeck-tui-tests --test tui_workspace instruction_inspector_renders_lea_address_constants`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`
