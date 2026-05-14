# Plan Report -- RevDeck v0.1 Binary Triage MVP

## Summary

- Phase: RevDeck v0.1 Binary Triage MVP
- Phase directory: `.workflow/scratch/20260513-revdeck-v01-binary-triage`
- Plan file: `.workflow/scratch/20260513-revdeck-v01-binary-triage/plan.json`
- Task count: 6
- Wave count: 4
- Scope: Binary Triage only; Trace/Diff/Firmware/Crash/Protocol/Memory Labs and plugin marketplace remain out of v0.1.

## Source Inputs

The plan consumed `RevDeck.txt`, the v0.1 scratch context and index, brainstorm context/specification/feature index, and E1-E4 exploration files. The consistent direction across those sources is to prove a terminal-native reverse engineering workspace loop rather than a full reverse-engineering suite.

## Exploration Findings Used

E1 architecture emphasized SQLite as source of truth, stable ObjectRef IDs, objects/edges, analysis_runs, importer/analyzer boundaries, and keeping future labs behind schema hooks.

E2 implementation recommended a Rust workspace with CLI/core/db/index/tui crates, deterministic fixtures, fixture-first indexing tests, Ratatui plus crossterm, and a small explicit command set before any broad query language.

E3 UX/product emphasized the three-pane TUI, Function Radar as the "what should I inspect next" surface, ObjectRef-driven universal navigation, and analysis memory as first-class project data.

E4 risk/test emphasized determinism: stable IDs, checked-in fixtures, boundary_confidence, structured score reasons, parser/resolver/executor separation, migration safety, re-index preservation, and canonical JSON export.

## Plan Overview

Wave 1 establishes the durable project foundation:

- `TASK-001` creates the workspace scaffold, SQLite migrations, stable ObjectRef/object keys, objects/edges, analysis_runs, transaction boundaries, and deterministic fixture harness.

Wave 2 builds indexed facts and object access in parallel:

- `TASK-002` implements native binary ingest/indexing for deterministic ELF fixtures, including sections, symbols, imports, strings, function candidates, xref/call edges, structured diagnostics, and boundary_confidence.
- `TASK-003` implements object graph queries, universal navigation, history, and command parser/resolver/executor layering.

Wave 3 adds triage intelligence and analyst-owned data:

- `TASK-004` implements Function Radar with structured score reasons, evidence ObjectRefs, deterministic sorting, and boundary_confidence visibility.
- `TASK-005` implements analysis memory, findings, evidence links, pre-export validation, and Markdown/JSON export without allowing re-index to break analyst data.

Wave 4 integrates the product surface:

- `TASK-006` delivers the three-pane Ratatui workspace with Overview, Binary Map, Function Radar, Functions, Strings, Imports, Notes, Findings, inspector, command bar, reducer tests, and terminal-size fallbacks.

## Verification Strategy

The plan requires `cargo fmt`, `cargo clippy`, `cargo test --workspace`, fixture determinism tests, re-index preservation tests, command mutation-safety tests, TUI reducer/render tests, and JSON/Markdown export tests. The core acceptance path is: import fixture binary, inspect Function Radar reason evidence, navigate through ObjectRefs, add note/tag/rename/status, create finding evidence, export Markdown/JSON, reopen/re-index, and verify every stable link still resolves.

## Confidence

Overall confidence: 0.87. Coverage is high because the plan directly maps F-001 through F-006 and keeps F-007/F-008 as schema/navigation hooks only. The weakest area is estimation accuracy because exact function/xref quality depends on parser/disassembly behavior against fixtures; the plan mitigates that with boundary_confidence and deterministic fixture tests.
