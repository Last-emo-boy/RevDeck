# F-007 Developer Tooling And Test Harness

## Purpose

Make SDK adoption practical and keep plugin behavior compatible, deterministic, and safe.

## User Value

Plugin authors can scaffold, validate, run, and test plugins headlessly. Analysts get fewer broken plugins and clearer diagnostics.

## Requirements

- SDK MUST include manifest/schema validation.
- SDK SHOULD include `revdeck plugin test`.
- Fixture replay SHOULD compare normalized graph bundles and accepted event digest sequences, not private SQLite tables.
- The harness MUST test permission denial and deterministic replay.
- TUI plugin surfaces SHOULD have small/standard/wide terminal contract tests.

## Tooling

- `revdeck plugin new <template>`
- `revdeck plugin validate <path>`
- `revdeck plugin test <path>`
- `revdeck plugin run --dry-run <id>`
- Rust helper crate for ObjectBatch construction.
- Language-neutral JSONL protocol fixture runner for Python/shell adapters.

## Fixtures

- Tiny ELF/PE/Mach-O or synthetic exports.
- Ghidra/rizin JSON.
- Trace JSONL, including malformed and duplicate events.
- ASAN/UBSAN/panic logs.
- binwalk-like firmware tree.
- tshark JSON.
- Volatility JSON.
- Golden graph summary and diagnostics per fixture.

## Test Strategy

- Manifest negative tests.
- Graph delta validation.
- Sandbox permission matrix.
- Deterministic replay.
- Compatibility across SDK minor versions.
- Reducer-first CLI/TUI regression tests.

## Rollout Notes

Ship a minimal harness with the SDK preview. It is part of the product contract, not optional polish.
