# 20260514 execute native mov constant copy

## Intent

Continue the native analyzer path by propagating known register constants through direct register moves.

## Scope

- `mov dst, src` now creates a `constant_writes` fact for `dst` when `src` has a known local constant.
- The instruction still records `constant_sources` for the read register.
- Copy chains such as `mov rax,0x2a; mov rdx,rax; mov rcx,rdx` now preserve the constant through each register.
- Existing stale-state clearing still applies when a destination register is overwritten.

## Constraints

- This slice is local and linear within a scanned block/function pass.
- It only handles direct register-to-register `mov`.
- It does not propagate through arithmetic, memory loads, or cross-basic-block joins.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_constant_reads_reference_latest_local_constant_writer`
  - `cargo clippy -p revdeck-index --lib --tests -- -D warnings`

## Files

- `crates/revdeck-index/src/lib.rs`
