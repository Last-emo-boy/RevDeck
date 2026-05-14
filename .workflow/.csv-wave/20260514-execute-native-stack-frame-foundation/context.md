# 20260514 execute native stack-frame foundation

## Intent

Continue native analyzer maturation toward deeper reverse engineering workflows by adding conservative stack-frame facts for common x86-64 function prologues.

## Scope

- Added native decode coverage for:
  - `mov rbp,rsp`
  - `sub rsp, imm8`
  - `sub rsp, imm32`
- Added function-level metadata:
  - `frame_pointer`
  - `stack_frame_size`
- Stack-frame extraction is conservative:
  - `frame_pointer = rbp` only for `push rbp; mov rbp,rsp`
  - stack frame size only from decoded `sub rsp, imm`
- Function object metadata now persists the stack-frame facts.
- TUI Function Inspector renders:
  - `Native Function`
  - `Frame pointer: ...`
  - `Stack frame: ... bytes`

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index synthetic_pe_function_metadata_includes_stack_frame`
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`

