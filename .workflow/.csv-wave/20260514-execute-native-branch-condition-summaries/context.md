# 20260514 execute native branch condition summaries

## Intent

Continue the native analyzer path by turning flag-producer links into readable branch condition summaries.

## Scope

- Instruction metadata now includes:
  - `condition_summary`
- Function scanning remembers the latest local `cmp` or `test` flag producer.
- Conditional branches render concise summaries where supported:
  - `je if rax == 0x7f`
  - `jne if rax != 0`
  - `je if rax == rcx`
- Unsupported conditions fall back to a conservative raw producer summary.
- TUI Native Instruction inspector renders:
  - `Condition: ...`

## Constraints

- This slice is display-oriented and does not alter CFG or branch target inference.
- It is local and linear within the scanned function.
- It does not perform symbolic execution or signedness proof beyond mnemonic-based hints.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_conditional_branch_references_immediate_flag_producer`
  - `cargo test -p revdeck-index native_conditional_branches_reference_recent_flag_producer`
  - `cargo test -p revdeck-tui-tests --test tui_workspace inspector_and_graph_lab_render_condition_source`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`
