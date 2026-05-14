# 20260514 execute native register def-use

## Intent

Continue the native analyzer path by promoting instruction register read/write summaries into simple local def-use facts.

## Scope

- Added instruction metadata:
  - `register_sources`
- During linear function scanning, each register read links to the latest local instruction that wrote the same register.
- Register def-use links are persisted as instruction-to-instruction `references` xrefs.
- TUI Native Instruction inspector renders jumpable register source lines, e.g. `Register source rax`.

## Constraints

- This slice is intentionally local and linear. It does not attempt full cross-basic-block reaching-definition analysis yet.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_register_reads_reference_latest_local_writer`
  - `cargo test -p revdeck-index native_instruction_register_access_summaries_include_memory_address_registers`
  - `cargo test -p revdeck-tui-tests --test tui_workspace inspector_and_graph_lab_render_condition_source`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

