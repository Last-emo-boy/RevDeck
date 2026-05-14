# Native not/neg r32 registers

## Goal

Extend the native analyzer with register-only 32-bit `not` and `neg` decoding plus constant folding, while preserving the native-only product boundary.

## Changes

- Added native decoding for `f7 /2` and `f7 /3` register-only `not r32` and `neg r32`.
- Added non-W REX.B support for extended 32-bit registers such as `r8d` and `r9d`.
- Preserved `f7 /0` 32-bit `test r32, imm32` decoding by trying unary group decoding before test-immediate fallback.
- Added in-place read/write tracking and constant folding for unary `not` and `neg`.
- Added non-W REX.B 32-bit immediate `cmp` decoding so extended-register folded constants can be verified with native 32-bit comparisons.
- Normalized comparison known-outcome evaluation to the condition operand width before equality, unsigned, and signed branch checks.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_32_bit_not_neg_registers -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_not_neg_registers_fold_known_constants -- --nocapture`
- `cargo test -p revdeck-index native_decoder_decodes_cmp_and_test_immediate_operands -- --nocapture`
- `cargo test -p revdeck-index native_32_bit_cmp_immediate_branches_use_known_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.
