# Native CFG Foundation Execution

Date: 2026-05-14
Plan: `.workflow/scratch/20260514-plan-native-analyzer-r2-class/plan.json`
Slice: M3N-A Instruction And Block Persistence

## Completed

- Removed the unfinished external adapter path from product code, tests, fixtures, README and active workflow artifacts.
- Added native analyzer object kinds:
  - `instruction`
  - `basic_block`
- Added native control-flow relation kind:
  - `control_flow`
- Added schema migration `0007_native_cfg.sql`:
  - `instructions`
  - `basic_blocks`
  - `cfg_edges`
- Added typed repository records and upsert methods for instruction, basic block and CFG edge facts.
- Extended the native indexer to emit conservative instruction streams, basic blocks and CFG edges from binary bytes.
- Loaded native basic block and instruction objects into the TUI workspace snapshot so Graph Lab can traverse function -> block -> instruction relations.
- Extended `revdeck stats` with `instructions`, `basic_blocks` and `cfg_edges` counts.
- Updated README to describe Native Analyzer foundation and native analyzer roadmap.

## Verification

- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed.
- Targeted TUI verification `cargo test -p revdeck-tui-tests project_snapshot_loads_native_cfg_objects_for_graph_lab` passed.
- External adapter grep audit passed:
  - searched `README.md crates tests fixtures .workflow`
  - no active product references to removed external adapter keywords.

## Current limitation

The native instruction scanner is deliberately conservative. It recognizes a small x86/x64 opcode slice sufficient to create durable instruction/block/CFG facts, but it is not yet a full disassembler. This is the intended foundation for the next milestone: instruction-driven xrefs and richer graph modes.
