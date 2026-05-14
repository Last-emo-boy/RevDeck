# System Architect Analysis

## Architecture Direction
RevDeck should use a layered architecture:
- TUI Frontend: Ratatui-style workspace, keybindings, command bar, view state.
- Workspace Layer: lenses, navigation history, object inspector, command routing.
- Core Engine: project database, graph, query, jobs, notes, findings, scoring.
- Analysis Adapters: ELF/PE parsing, strings/imports/functions, external tool imports.
- External Tools: Ghidra, radare2/rizin, Frida, Volatility, tshark, binwalk outputs.

## Data Model
Initial entities SHOULD include:
- Artifact: imported target, source path, hash, type, metadata.
- Object: normalized addressable item such as file, section, function, string, import, xref, note, tag, finding.
- Edge: typed relationship such as CONTAINS, REFERENCES, CALLS, IMPORTS, EVIDENCE_FOR.
- AnalysisRun: deterministic job record with adapter version, input hash, status, errors.
- Annotation: user-owned note, tag, rename, status, hypothesis, or evidence link.

SQLite SHOULD be the source of truth. Stable IDs MUST survive TUI sessions and export/import round trips.

## State Machine
Project states:
- Empty: project exists, no artifacts.
- Imported: artifacts registered, indexing pending.
- Indexed: core objects available.
- Reviewed: user annotations or findings exist.
- Exported: report bundle generated.

Analysis run states:
- queued -> running -> completed
- queued -> running -> failed
- completed -> superseded when input or adapter version changes

## Error Handling
- Import errors MUST be recorded with artifact path, adapter, and user-readable cause.
- Partial indexing SHOULD preserve successful objects and mark failed stages.
- External adapter failures MUST NOT corrupt project state.
- Malformed external JSON SHOULD produce structured diagnostics and fixtureable test cases.

## Observability
Track at least:
- import_duration_ms
- indexed_object_count
- functions_indexed
- strings_indexed
- xrefs_indexed
- scoring_duration_ms
- command_latency_ms
- db_query_duration_ms
- failed_adapter_runs

## Configuration Model
Configuration SHOULD include project-local settings and user settings:
- enabled adapters
- scoring weights
- keybindings
- external tool paths
- report output defaults
- cache limits

## Integration Boundaries
F-008 should be planned as contracts, not implementation sprawl. The first adapter can be native ELF parsing, with external adapters mocked through JSON fixtures.
