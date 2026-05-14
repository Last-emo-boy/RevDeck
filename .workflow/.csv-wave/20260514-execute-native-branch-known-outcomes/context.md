# 20260514 execute native branch known outcomes

## Intent

Continue the native analyzer path by using local register constants to annotate conditional branch summaries with known outcomes.

## Scope

- Branch condition summaries now consult current local register constants.
- Supported local outcomes include:
  - `jne if rax != 0x2a (known not taken)`
  - `jne if rax != 0x7f (known taken)`
  - `jne if rcx != 0 (known not taken)`
- Existing summaries still work when no local constant is known.
- The implementation remains conservative and block-local.

## Constraints

- This slice does not perform cross-basic-block reaching constant analysis.
- Known outcome annotations are only emitted when operands can be resolved to direct constants in the current local scan state.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_conditional_branch_summary_marks_known_constant_outcomes`
  - `cargo test -p revdeck-index native_conditional_branch_references_immediate_flag_producer`

## Files

- `crates/revdeck-index/src/lib.rs`
