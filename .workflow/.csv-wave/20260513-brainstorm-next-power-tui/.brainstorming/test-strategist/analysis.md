# Test Strategist Analysis

## Test Strategy

The next iteration should keep the existing deterministic fixture approach. Every new surface should have reducer/state tests plus render snapshots where practical.

## Required Test Areas

- Graph Lab traversal tests: depth limits, relation filters, stable sort, broken refs, and source-to-sink path rendering.
- Command Deck parser/resolver tests: fuzzy search ranking, action preview, mutation gating, and command history.
- ObjectBatch commit tests: idempotency, permission denial, dangling refs, duplicate facts, rollback on invalid batch, and contribution provenance.
- Adapter runner tests: timeout, output cap, stderr redaction, invalid JSON, denied permissions, and deterministic replay fixture.
- Binary Map diagnostics tests: PE/ELF known fixtures, unknown magic, packed-like entropy fixture, and no-regression import/string counts.
- TUI performance tests: large function/string/import lists should not require loading unbounded rows or rendering unstable layouts.

## Gates

- `cargo fmt --all -- --check`.
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `cargo test --workspace`.
- CLI smoke for adapter plugin test/run/commit.
- TUI reducer tests for new shortcuts and command deck.
- Snapshot tests for Graph Lab, Binary Map 2.0, Command Deck, and small terminal fallback.
