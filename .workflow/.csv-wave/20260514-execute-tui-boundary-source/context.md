# 20260514 execute TUI boundary source

## Intent

Make native function recovery evidence visible in the TUI. Analyzer slices now distinguish symbol, entrypoint, call-target, and heuristic function boundaries; the Inspector should show that source directly.

## Scope

- Function Inspector now renders `Boundary source: <source>` alongside size, radar score, and boundary confidence.
- Existing Function Radar inspector snapshot now asserts boundary source visibility.
- No data model or analyzer dependency changes.

## Evidence

- Focused test passed:
  - `cargo test -p revdeck-tui function_radar_inspector_snapshot`

## Files

- `crates/revdeck-tui/src/lib.rs`

