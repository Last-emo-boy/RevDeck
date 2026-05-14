# 20260514 execute native epilogue foundation

## Intent

Continue the native analyzer path by adding stack cleanup and frame epilogue facts without relying on external reverse engineering tools.

## Scope

- Decoded common x86-64 epilogue instructions:
  - `add rsp, imm8`
  - `add rsp, imm32`
  - `leave`
  - `pop rbp`
- Added function-level metadata:
  - `stack_cleanup_size`
  - `epilogue_kind`
  - `has_frame_epilogue`
- Increased the native function seed size from 16 to 32 bytes so short native functions can include prologue, stack slot references, cleanup, and `ret` before terminal refinement narrows the final extent.
- TUI Function Inspector now renders:
  - `Stack cleanup: <n> bytes`
  - `Epilogue: <kind>`

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_decodes_stack_cleanup_and_epilogue_instructions`
  - `cargo test -p revdeck-index synthetic_pe_function_metadata_includes_stack_frame`
  - `cargo test -p revdeck-index synthetic_pe_direct_call_targets_create_heuristic_functions`
  - `cargo test -p revdeck-index synthetic_pe_fixture_indexes_sections_strings_and_entrypoint`
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`
  - `cargo test -p revdeck-tui-tests --test tui_workspace function_radar_inspector_snapshot`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

