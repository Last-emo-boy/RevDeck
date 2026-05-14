# 2026-05-14 Native ModRM/SIB Operand Decode

## Goal

Continue RevDeck's native analyzer maturity by expanding typed operand coverage beyond RIP-relative special cases.

## Changes

- Extended `DecodedOperand` memory metadata with:
  - `index`
  - `scale`
- Added `OperandRole::Source` so `mov` operands can distinguish source memory/register operands from destinations.
- Added a compact x86-64 ModRM/SIB decoder path for REX.W `mov`:
  - `mov r64, r/m64`
  - `mov r/m64, r64`
- Added memory operand support for:
  - base + disp8/disp32, including negative displacement text such as `[rbp-0x8]`
  - SIB base + index * scale + disp
  - SIB displacement-only memory forms
- Kept RIP-relative handling intact through the existing dedicated path.
- Preserved current DB schema and `instructions.operands_text`; richer structure remains in instruction object metadata via `typed_operands`.

## Tests

Added focused coverage in `crates/revdeck-index/src/lib.rs`:

- `native_decoder_decodes_modrm_sib_memory_operands`
  - `mov rax,qword ptr [rbp-0x8]`
  - `mov qword ptr [rsp+rax*4+0x20],rcx`
  - `mov rax,qword ptr [0x1234]`

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit:
  - `rg -n "radare2|r2 |r2_|ImportJson|import-json|com\.revdeck\.adapters|ghidra" README.md crates tests fixtures .workflow`
  - no matches; `rg` exited with code `1`, expected for zero matches

## Native-Only Position

This iteration remains fully native. No radare2, Ghidra, adapter, import-json, or external CLI route was introduced.

## Next Candidate Slice

- Add REX register extension support (`r8`-`r15`) and operand-size variants.
- Add typed operand support for `cmp`, `test`, arithmetic, and stack memory patterns.
- Surface `typed_operands` in TUI Graph Lab / inspector details.
