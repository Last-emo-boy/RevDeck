# 20260514 execute native stack slots

## Intent

Build on the native stack-frame foundation by surfacing concrete stack slot references discovered from typed memory operands.

## Scope

- Added function-level `stack_slots` metadata.
- Stack slots are collected from decoded typed memory operands whose base is `rbp` or `rsp`.
- Slots are keyed by `(base, offset)`, deduplicated, and include `width_bits` when known.
- Function object metadata now persists `stack_slots`.
- TUI Function Inspector renders:
  - `Stack slots`
  - up to 4 rendered slot entries, e.g. `rbp-0x8 (64-bit)`

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index synthetic_pe_function_metadata_includes_stack_frame`
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`
  - `cargo test -p revdeck-tui-tests --test tui_workspace function_radar_inspector_snapshot`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

