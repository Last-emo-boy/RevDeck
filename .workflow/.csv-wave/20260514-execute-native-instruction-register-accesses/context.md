# 20260514 execute native instruction register accesses

## Intent

Continue the native analyzer path by deriving instruction-level register read/write summaries from typed operands.

## Scope

- Added instruction metadata:
  - `register_reads`
  - `register_writes`
- Register operands are classified by operand role.
- Memory operands contribute their base/index registers as reads, including destination memory operands such as `[rsp+rax*4]`.
- TUI Native Instruction inspector renders:
  - `Reads: ...`
  - `Writes: ...`

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_instruction_register_access_summaries_include_memory_address_registers`
  - `cargo test -p revdeck-tui-tests --test tui_workspace inspector_and_graph_lab_render_condition_source`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

