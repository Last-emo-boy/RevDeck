# TASK-002 Summary

Status: completed

Implemented the v0.1 native binary ingest path for deterministic ELF fixtures. The importer registers artifacts by stable `ObjectRef`, SHA-256, source path, size, kind, format, architecture, and import status; starts and finishes `analysis_runs`; persists sections, symbols, imports, strings, function candidates, xrefs, and edges; and records structured diagnostics for corrupt artifacts.

Key work:
- Added artifact metadata and structured diagnostic models in `revdeck-core`, including `boundary_confidence` values.
- Added schema migration `0002_binary_index.sql` for artifact indexing metadata and text function boundary confidence.
- Extended DB repositories for typed section/symbol/function/string/import/xref writes, edge confidence/metadata, idempotent indexed-fact cleanup, and query helpers.
- Implemented `revdeck-index` native ELF ingest using checked-in fixtures, SHA-256 hashing, ASCII/UTF-16 string scanning, symbol/entrypoint/import-thunk/heuristic function candidates, and `CONTAINS`, `REFERENCES`, `CALLS_IMPORT`, `XREF_FROM`, and `DERIVED_FROM` edges.
- Wired `revdeck import` to the indexing pipeline and made corrupt fixture imports return structured JSON failure while persisting a failed `analysis_run`.
- Added deterministic source-controlled ELF/corrupt/unsupported fixtures and manifest SHA-256/expected metadata.

Verification:
- `rg "boundary_confidence" crates/revdeck-core crates/revdeck-index crates/revdeck-db`: passed.
- `rg "CALLS_IMPORT|XREF_FROM|REFERENCES|DERIVED_FROM" crates`: passed.
- `rg "source-controlled|sha256|expected" fixtures/manifest.json tests`: passed.
- `cargo test -p revdeck-index fixture_minimal_elf`: passed.
- `cargo test -p revdeck-index fixture_stripped_elf`: passed.
- `cargo test -p revdeck-index fixture_sensitive_imports`: passed.
- `cargo test -p revdeck-index corrupt_artifact_records_failed_run`: passed.
- `cargo test -p revdeck-db reindex_idempotent_indexed_facts`: passed.
- `cargo test -p revdeck-index`: passed, 4 tests.
- `cargo test --workspace`: passed, 19 tests across workspace crates.
- CLI corrupt fixture check: `revdeck import` exited with code 1, returned structured JSON with `elf_parse_failed`, and SQLite `analysis_runs` recorded `status=failed` with `error_json`.

Scope guard:
- Did not implement Function Radar, Analysis Memory, findings export, Ratatui workspace, Graph Lab, or external tool adapters.
