# Data Architect Cross-Cutting Decisions

## 1. Stable Object Graph Boundary

RevDeck should treat the object graph as the public integration surface and SQLite as an implementation detail. Current code already points this way: stable object keys encode deterministic identity, `objects` and `edges` form the cross-navigation layer, and `ObjectGraphQuery` offers get/search/relation traversal without exposing SQL.

The SDK should publish a schema-stable graph API with transactions:

- `begin_run(plugin, version, inputs, config)`
- `write_batch(objects, edges, attributes, datasets, artifacts, diagnostics)`
- `finish_run(status, summary)`
- `query_objects(predicate, projection, page)`
- `traverse(root, direction, edge_filter, limits)`

The write path MUST validate kind, key, schema, permission, and provenance before persistence. A plugin should never decide which core table to mutate. This allows RevDeck to refactor from JSON fields to typed columns, add indexes, or split tables without breaking plugins.

For v0.9, use a controlled core object vocabulary. Recommended additions to current kinds:

- Artifact and file family: `file`, `directory`, `firmware_image`, `derived_artifact`
- Binary family: `basic_block`, `instruction`
- Trace family: `trace`, `trace_event`, `syscall_event`, `memory_event`
- Crash family: `crash`, `stack_frame`, `input_sample`
- Protocol family: `protocol_capture`, `message`, `field`
- Memory family: `memory_image`, `process`, `module`, `region`, `handle`
- Diff family: `version`, `diff_change`

Plugins can extend these through typed attributes first. Custom object kinds should require a later SDK level because they affect navigation, query planning, export, and migration compatibility.

## 2. Identity And Idempotency

Stable keys need explicit construction rules per object family. The current keys are deterministic for artifacts, functions, strings, imports, xrefs, scores, annotations, and findings. Extend the rules:

- Content-derived artifacts: hash plus normalized project-relative path.
- External tool objects: source artifact key plus external tool namespace plus external stable ID.
- Trace events: trace artifact key plus event ordinal or source timestamp plus sequence hash.
- Crash frames: crash artifact key plus normalized frame index plus function/module/address tuple.
- Protocol messages: capture artifact key plus packet/message index plus direction.
- Plugin attributes: subject ref plus plugin namespace plus schema ID plus attribute key.

Run ID should normally not be part of object identity, or re-runs will create duplicates. Run ID belongs in provenance. Exceptions are intentionally ephemeral outputs such as a one-off diagnostic object or a draft suggestion that the user has not accepted.

## 3. Schema Registry And Typed Attributes

`metadata_json` is useful for early iteration but cannot be the only public extension model. Add a host-owned schema registry:

- `schema_id`: namespaced, for example `com.acme.frida.trace_event.v1`
- `owner_plugin_id`
- `schema_kind`: object_attributes, edge_attributes, dataset, report_fragment, config
- `version`
- `json_schema`
- `compatibility`: additive, breaking, deprecated
- `registered_at`

Typed attributes should be stored as first-class facts, not hidden inside an arbitrary object JSON blob:

- subject object ref
- namespace
- schema ID and version
- key
- typed value, stored with normalized scalar columns where practical plus JSON fallback
- source run and plugin provenance
- confidence and visibility flags

This makes filters such as "functions where rule.risk = high and calls import system" possible without teaching plugins SQL.

## 4. Plugin-Owned Tables And Datasets

Arbitrary plugin DDL should be out of scope for the first stable SDK. It creates upgrade, backup, query, and security problems. However, some domains need high-volume tabular data: traces, packets, memory maps, fuzz cases, and symbol tables.

Recommended compromise:

1. RevDeck owns common high-volume dataset families for Trace Lab, Protocol Lab, Crash Lab, Firmware Lab, and Memory Lab.
2. Plugins declare dataset schemas and indexes in the manifest.
3. The host creates or maps storage through a dataset API.
4. Plugins query datasets through typed cursors and predicates.

If plugin-owned tables are later required, they should be namespaced, created only from declarative schemas, migrated only by host-approved operations, and inaccessible through raw SQL. The SDK should call them "extension datasets" rather than "tables" to keep the public contract storage-agnostic.

## 5. Migrations

Separate core migrations from plugin schema migrations.

Core:

- RevDeck continues to own project schema migrations and can rewrite internal tables.
- A project records core schema version and SDK compatibility version.

Plugin:

- Each installed plugin records plugin ID, plugin version, declared schema version, install time, and trust level.
- `plugin_schema_migrations` records applied plugin migration IDs and checksums.
- Plugin migrations are declarative operations: register schema, deprecate schema, backfill attribute, create dataset, add index, transform report fragment.
- Migrations MUST run transactionally and write diagnostics.
- Downgrade should be treated as unsupported unless the manifest declares an explicit reversible migration.

A plugin upgrade cannot silently reinterpret old facts. It must either keep reading old schema versions, migrate them, or mark them deprecated while preserving original provenance.

## 6. Provenance Model

Every plugin-created fact needs provenance. Minimum fields:

- plugin ID and version
- capability and command
- analysis run ID
- input artifact refs and content hashes
- input hash and config hash
- schema ID and version
- timestamp
- confidence
- diagnostics summary

Current `source_run_id` should remain as a compact pointer, but the graph needs many-to-many contribution records. Multiple plugins may assert the same edge or attach different labels to the same function. RevDeck should preserve all contributions and derive canonical display state through deterministic merge rules:

- analyst annotations override plugin display labels
- highest confidence does not erase lower confidence
- conflicting typed attributes are visible as conflicts
- accepted findings remain stable even if plugin suggestions are later withdrawn

## 7. Artifact Storage

Store large data outside SQLite and reference it from SQLite.

Recommended layout:

- `.revdeck/artifacts/sha256/<hash>` for imported immutable blobs
- `.revdeck/derived/<run-id>/<hash>` for plugin outputs
- `.revdeck/datasets/<dataset-id>/...` for large event or packet stores
- `.revdeck/reports/` for generated reports

SQLite stores object refs, hashes, size, MIME or kind, format, architecture, source path, stored URI, redaction status, and provenance. Derived artifacts should link to their parents through `derived_from` edges and should be reproducible from run metadata when possible.

Project export MUST verify hashes. Missing blobs should degrade to metadata-only exports with explicit diagnostics, not silent partial bundles.

## 8. Query API

The query API should support:

- Object lookup by ref.
- Text search with kind filters.
- Attribute predicates.
- Edge predicates and bounded graph traversal.
- Artifact and run filters.
- Score and reason filters.
- Evidence-chain expansion.
- Dataset cursors for high-volume streams.
- Pagination, limits, and stable sort keys.

Expose this as SDK structs and a compact query DSL, not SQL. The command bar can compile user expressions into the same query API. Lenses and exporters should use the same query surface so behavior remains consistent across TUI, CLI, tests, and plugins.

Private SQLite details should not leak into query errors. Return typed errors such as `UnsupportedPredicate`, `PermissionDenied`, `SchemaNotFound`, `QueryTooExpensive`, `InvalidProjection`, and `StaleCursor`.

## 9. Import And Export Formats

Plugin I/O should be streaming JSONL for the first SDK because it is inspectable, diffable, and easy for non-Rust adapters. Define canonical records:

- `artifact`
- `object`
- `edge`
- `attribute`
- `dataset_record`
- `score_reason`
- `draft_finding`
- `evidence_link`
- `diagnostic`

For project handoff, use a RevDeck bundle:

- `manifest.json`
- `project.json`
- `schemas/*.json`
- `runs.jsonl`
- `objects.jsonl`
- `edges.jsonl`
- `attributes.jsonl`
- `findings.jsonl`
- `datasets/<id>/records.jsonl` or later columnar files
- `artifacts/sha256/<hash>`

Report exports remain Markdown, JSON, and SARIF, but they should be projections from the same bundle-grade data model.

## 10. Cross-Feature Risks

F-002 is a prerequisite for nearly everything else. F-003 adapters, F-004 labs, F-005 scoring, and F-008 findings will fragment if each plugin invents its own data shape.

The main conflict is flexibility versus queryability. Arbitrary plugin objects and raw tables maximize plugin freedom but weaken migration, export, and TUI navigation. The recommended resolution is staged extensibility: typed attributes and host-managed datasets now, custom object kinds after the graph, query API, and export bundle have compatibility tests.

The second conflict is performance versus simplicity. JSON attributes are simple but poor for large traces and packets. The resolution is to keep the object graph as the navigation backbone and use dataset cursors for volume-heavy records.
