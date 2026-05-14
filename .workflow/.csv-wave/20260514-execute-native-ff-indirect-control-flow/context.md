# 20260514 execute native FF indirect control flow

## Intent

Continue native analyzer maturity toward a radare2-class reverse engineering TUI while keeping RevDeck independent of external reverse engineering adapters or compatibility layers.

## Scope

- Added native x86-64 `FF` group control-flow decoding:
  - `FF /2`: indirect `call r/m64`
  - `FF /4`: indirect `jmp r/m64`
- Added REX-prefixed `FF` handling for extended registers such as `jmp r8`.
- Reused existing ModRM/SIB memory operand decoding for indirect memory targets.
- Modeled indirect targets as typed operands with `CallTarget` or `BranchTarget` roles.
- Left dynamic target resolution intentionally unresolved; indirect register and non-absolute memory targets do not fabricate static function/block xrefs.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_decodes_indirect_call_and_jump_operands`
  - `cargo test -p revdeck-index native_cfg_scanner_closes_indirect_jump_without_static_target_xref`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`

