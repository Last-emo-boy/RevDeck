# 20260514 execute native argument register hints

## Intent

Continue the native analyzer path by adding lightweight calling-convention and argument-register hints without relying on external reverse engineering tools.

## Scope

- Added function metadata:
  - `calling_convention`
  - `argument_registers`
- Added ABI-aware argument register candidates:
  - PE: `windows-x64` with `rcx`, `rdx`, `r8`, `r9`
  - ELF: `sysv-x64` with `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
- Implemented a conservative read-before-write scan over the first 16 decoded instructions, stopping at the first call.
- TUI Function Inspector renders compact native ABI hints:
  - `ABI: windows-x64`
  - `Args: arg1: rcx`

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index synthetic_pe_function_metadata_includes_stack_frame`
  - `cargo test -p revdeck-index native_decoder_decodes_rex_extended_registers`
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`
  - `cargo test -p revdeck-tui-tests --test tui_workspace function_radar_inspector_snapshot`

## Files

- `crates/revdeck-index/src/lib.rs`
- `crates/revdeck-tui/src/lib.rs`
- `tests/tui/tests/tui_workspace.rs`

