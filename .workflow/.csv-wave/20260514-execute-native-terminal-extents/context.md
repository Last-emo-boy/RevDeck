# 20260514 execute native terminal extents

## Intent

Improve native function boundary quality without external analyzers. This slice makes heuristic function sizes stop at terminal instructions instead of including padding bytes after `ret` / terminal jumps.

## Scope

- `refine_function_extents` now accepts the artifact reference and can return model errors.
- Function end is additionally capped by the first decoded terminal instruction within the already conservative function span.
- Function `object_ref` is rebuilt after any size refinement, keeping the stable key's `size` component consistent with the persisted function size.
- Existing rules still apply first:
  - do not expand function sizes,
  - cap by the next known function start,
  - cap by containing section end.

## Evidence

- Focused test passed:
  - `cargo test -p revdeck-index synthetic_pe_direct_call_targets_create_heuristic_functions`
- The test asserts the entrypoint function stops at `call + ret` and that the function key contains the refined size.

## Files

- `crates/revdeck-index/src/lib.rs`

