# Wave Context: native sign-flag branches

## Goal

Improve native conditional branch explanations for sign-flag driven branches without introducing external analyzer dependencies.

## Changes

- Added native condition summaries for `js` and `jns` after `test` and `cmp` flag producers.
- Added known-outcome inference for common `test reg,reg` sign checks when the tested register has a tracked constant value.
- Added width-aware sign-bit helpers so sign checks use the known operand/register width where available.
- Preserved propagation into CFG edge metadata through the existing branch outcome path.
- Added focused coverage for:
  - `js if rax < 0 (known taken)`.
  - `jns if rax >= 0 (known taken)`.
  - CFG branch edge metadata carrying the known `js` outcome.

## Verification

- `cargo test -p revdeck-index native_sign_flag_branches_summarize_known_test_outcomes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This keeps the analyzer native-only and increases real-world branch explainability for compiler-generated sign checks.
