# Wave Context: native test bitmask branches

## Goal

Improve native branch explanations for common `test` bitmask checks and parity checks.

## Changes

- Added known-outcome inference for `test` result zero checks:
  - `je` after `test` now marks known taken/not taken when both operands are known.
  - `jne` after `test` now marks known taken/not taken when both operands are known.
- Added parity branch summaries for `jp` and `jnp`.
- Added known-outcome inference for parity checks using the low byte of the `test` result.
- Reused the existing condition summary and CFG edge outcome pipeline, so these outcomes also appear on graph edges.
- Added focused coverage for:
  - `je if (rax & 0x8) == 0 (known not taken)`.
  - `jp if parity(rax & 0x3) is even (known taken)`.
  - CFG fallthrough metadata for a known not-taken bitmask branch.

## Verification

- `cargo test -p revdeck-index native_test_bitmask_branches_summarize_known_outcomes -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "<external-compatibility-patterns>" README.md crates tests fixtures .workflow`
  - exit code `1`, meaning no matches.

## Notes

This slice improves native analyzer fidelity for feature flags, packer stubs, and bitmask-driven branch patterns without relying on external compatibility layers.
