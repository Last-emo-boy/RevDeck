# 20260514 execute native function extents

## Intent

Improve native CFG quality after call-target function discovery by preventing newly discovered functions from overlapping existing entrypoint or symbol-backed functions.

## Scope

- Added conservative function extent refinement after function candidate collection.
- Function sizes are only reduced, never expanded.
- A function's end is capped by:
  - the next known function start,
  - the containing section end,
  - its existing size.
- This keeps entrypoint and call-target CFG scans from decoding the same bytes as overlapping functions.

## Evidence

- Focused test passed:
  - `cargo test -p revdeck-index synthetic_pe_direct_call_targets_create_heuristic_functions`
- The test now asserts the entrypoint function is shortened to the call-target boundary.

## Files

- `crates/revdeck-index/src/lib.rs`

