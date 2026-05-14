# Wave Context: native zero-extended register aliases

## Goal

Propagate native constants across x86-64 32-bit GPR writes that zero-extend into their 64-bit aliases.

## Changes

- Added tracked constant aliasing for 32-bit GPR constant writes:
  - `eax` also tracks `rax`.
  - `ecx` also tracks `rcx`.
  - Extended registers `r8d..r15d` also track `r8..r15`.
- Kept visible instruction metadata unchanged: the instruction still reports its real written register such as `eax`.
- Cleared stale 64-bit alias constants when a 32-bit alias is written.
- Added focused coverage for `mov eax,0x2a; cmp rax,0x2a; je`, proving the branch becomes `known taken`.

## Verification

- `cargo test -p revdeck-index native_32_bit_constant_writes_propagate_zero_extended_aliases -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native dataflow fidelity for common x86-64 codegen without changing the stored instruction surface.
