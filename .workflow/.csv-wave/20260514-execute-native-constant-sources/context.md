# 20260514 execute native constant sources

## Intent

Continue the native analyzer path by linking register reads to the latest local constant-producing instruction.

## Scope

- Instruction metadata now includes:
  - `constant_sources`
- Function scanning maintains a local register constant state.
- A register read records the latest known constant source for that register.
- Any write to a register clears stale constant state before new constant writes are installed.
- Constant source links are emitted as instruction-to-instruction reference xrefs.
- TUI Native Instruction inspector renders jumpable lines such as:
  - `Constant source rax=0x2a`

## Constraints

- This is intentionally local and linear within the scanned function.
- It does not perform cross-basic-block reaching constant analysis yet.
- It records direct constant sources only; arithmetic propagation is out of scope for this slice.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_constant_reads_reference_latest_local_constant_writer`
  - `cargo test -p revdeck-tui-tests --test tui_workspace instruction_inspector_renders_constant_sources`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`
