# 20260514 execute native stack slot access roles

## Intent

Continue the native analyzer path by upgrading stack slots from discovered addresses into local-variable-like facts with access roles.

## Scope

- Added `accesses` to stack slot metadata.
- Mapped typed memory operand roles into stack slot access kinds:
  - `read`
  - `write`
  - `call_target`
  - `branch_target`
  - `data_reference`
  - `unknown`
- Deduplicated accesses per `(base, offset)` stack slot while preserving existing width metadata.
- TUI Function Inspector renders compact access summaries, e.g. `rbp-0x8 (64-bit, read/write)`.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index synthetic_pe_function_metadata_includes_stack_frame`
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`
  - `cargo test -p revdeck-tui-tests --test tui_workspace function_radar_inspector_snapshot`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

