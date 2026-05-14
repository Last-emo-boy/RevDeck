# Wave Context: native zero-extended def-use aliases

## Goal

Propagate native def-use evidence across x86-64 32-bit GPR writes that zero-extend into 64-bit aliases.

## Changes

- Reused the zero-extension alias map for register writer tracking.
- When a 32-bit GPR is written, its 64-bit alias is also tracked as written by the same instruction.
- Kept visible instruction metadata unchanged: `register_writes` still reports the actual decoded register such as `eax`.
- Added focused coverage for `mov eax,0x2a; mov rdx,rax`, proving the `rax` read references the `eax` writer and creates a native `References` xref.

## Verification

- `cargo test -p revdeck-index native_zero_extended_register_writes_reference_alias_readers -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native evidence paths without changing the decoded instruction surface.
