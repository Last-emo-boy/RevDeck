# System Architect Analysis

## Architecture Direction

The current architecture has strong foundations: stable ObjectRef values, SQLite persistence, query repositories, NavigationLens, Function Radar reasons, and Plugin SDK dry-run validation. The next step should reuse these rather than adding a separate graph engine or UI extension runtime.

## Key Technical Moves

- Promote LocalGraph from a secondary render path into a first-class workspace lens with query-backed traversal depth, relation filters, and current-object context.
- Add ObjectBatch commit as a host-owned transaction. The host validates refs, permissions, provenance, and idempotency before inserting objects, edges, attributes, diagnostics, and plugin run records.
- Add adapter runner records with command, manifest digest, input digest, output digest, status, duration, stdout/stderr caps, and sanitized diagnostics.
- Keep plugin facts separable by source_run_id or contribution metadata so users can hide, replay, or remove plugin contributions later.
- Add cached TUI snapshots or paged query models for large object lists; current 500-row loads are acceptable for MVP but will not scale to firmware or trace imports.

## Data Model Additions

- plugin_contributions: object key, plugin_run_id, fact kind, digest, commit status.
- object_attributes or typed_attributes: host-owned key/value extension facts with provider and schema id.
- triage_items: derived or materialized queue entries with state, priority, target object, source reason, and finding link.
- job_runs: shared run record for import, index, plugin, export, and future analysis tasks.

## Constraints

- ObjectBatch commit MUST be idempotent.
- Adapter execution MUST be disabled for network/process escalation unless manifest and CLI flags permit it.
- TUI graph rendering MUST degrade to table form when graph width is too large.
- Background jobs SHOULD be cancellable or at least visibly auditable.
