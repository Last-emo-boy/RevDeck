# 2026-05-14 TUI Condition Source Visibility

## Goal

Make native condition-source analysis visible in RevDeck's TUI instead of leaving it only in database metadata and xrefs.

## Changes

- Inspector now renders a `Native Instruction` section for selected instruction objects.
- The section includes:
  - decoded mnemonic and operands
  - `flow_kind`
  - branch target / data target when present
  - `condition_source` as a jumpable inspector target
  - first typed operands from `typed_operands`
- Graph Lab / local relations now labels instruction-to-instruction condition xrefs as:
  - `Condition source: <branch> depends on <cmp/test>`
- Kept the implementation TUI-local and schema-compatible; no DB migration required.

## Tests

Added focused coverage in `tests/tui/tests/tui_workspace.rs`:

- `inspector_and_graph_lab_render_condition_source`
  - constructs a branch instruction with `condition_source`
  - verifies inspector renders native instruction and condition source
  - verifies Graph Lab renders condition-source relation text

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

- Add immediate-form decoding for `cmp r/m64, imm8/imm32` and `test r/m64, imm32`.
- Add cross-basic-block condition-source tracking for straight-line fallthrough.
- Add a compact TUI operand table once typed operands cover more instruction families.
