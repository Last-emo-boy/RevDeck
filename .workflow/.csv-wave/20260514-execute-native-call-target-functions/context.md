# 20260514 execute native call-target functions

## Intent

Improve RevDeck native analyzer function discovery for stripped or symbol-poor binaries while keeping analysis fully native and independent from external reverse engineering tools.

## Scope

- Added a conservative function discovery pre-scan over executable/text sections.
- Direct `call rel32` targets that land inside the same executable section are promoted to function candidates.
- New candidates use:
  - `boundary_source = "call_target"`
  - `boundary_confidence = "heuristic"`
  - name format `sub_<address>`
- Existing symbol and entrypoint functions keep priority; call-target candidates do not duplicate known addresses.
- Formal CFG collection now sees these function candidates in the same analysis run, enabling native `calls` edges to resolve immediately.

## Evidence

- Focused test passed:
  - `cargo test -p revdeck-index synthetic_pe_direct_call_targets_create_heuristic_functions`

## Files

- `crates/revdeck-index/src/lib.rs`

