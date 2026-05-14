# Data Architect Analysis

## Summary

RevDeck already has the right seed shape for an extensible reverse-engineering workspace: SQLite-backed projects, stable object keys, `objects`, `edges`, `analysis_runs`, scores, annotations, findings, and an `ObjectGraphQuery` trait that hides direct SQL from consumers. The plugin SDK should preserve that direction and formalize it into a stable data contract. Plugins MUST contribute graph facts through host APIs, not by writing private SQLite tables.

The data architecture decision is a two-layer model:

1. Core object graph: durable RevDeck-owned object families, edge kinds, artifacts, runs, evidence links, findings, scores, and query APIs.
2. Extension facts: plugin-declared typed attributes, datasets, derived artifacts, score reasons, and draft findings that are validated by a schema registry and attached to core objects with provenance.

This keeps the SDK useful for Ghidra exports, traces, crashes, pcaps, firmware trees, and rule packs without making every plugin depend on the current database layout.

## F-001 Plugin Manifest And Capability Model

The manifest MUST declare data contracts, not only executable metadata. Add sections for:

- `schemas`: object attribute schemas, edge metadata schemas, dataset schemas, report section schemas.
- `writes`: allowed object kinds, edge kinds, attribute namespaces, finding proposal scopes, artifact output scopes.
- `migrations`: plugin schema version, supported upgrade paths, rollback policy, compatibility with RevDeck schema versions.
- `indexes`: declared query predicates needed by lenses or analyzers, subject to host approval.

The host should reject manifests that request direct database access. A plugin can request `write.objects:function`, `write.attributes:com.vendor.rulepack`, or `write.dataset:trace_events`, but the host maps those to controlled APIs.

## F-002 Stable Schema And Object Graph SDK

This is the foundation. RevDeck SHOULD publish SDK types for:

- `ObjectRef { kind, stable_key }`
- `ArtifactRef { object_ref, content_hash, format, storage_uri }`
- `EdgeFact { source, target, kind, confidence, attributes }`
- `TypedAttribute { subject, namespace, schema_id, key, value, provenance }`
- `AnalysisRunRef { id, plugin_id, plugin_version, input_hash, config_hash }`
- `EvidenceLink { subject, evidence, role, order, note }`

The current single `source_run_id` field is useful but insufficient once multiple plugins enrich the same object. Add contribution records such as `object_contributions`, `edge_contributions`, and `attribute_contributions`, with run ID, plugin ID, schema version, timestamp, and confidence. Object rows remain canonical summaries; contributions preserve who asserted what.

RevDeck SHOULD keep core object kinds controlled by the host for v0.9. Plugins MAY define namespaced typed attributes and datasets first. Plugin-defined object kinds can come later after query, navigation, export, and migration semantics are stable.

## F-003 Importer And Adapter SDK

Importers should output an idempotent `ObjectBatch` transaction: artifacts, objects, edges, attributes, datasets, diagnostics, and derived blobs. Adapters for Ghidra, radare2, Frida, ASAN logs, Volatility, binwalk, tshark, and generic JSONL should normalize source data into RevDeck schemas.

Each imported external file or stream should become an Artifact, even when it is derived from another artifact. The graph then connects binary functions to external symbols, trace events, crash frames, firmware paths, packets, or memory regions through `derived_from`, `appears_in_trace`, `appears_in_crash`, `contains`, and `evidence_for` style edges.

## F-004 Specialized Lab Extension Points

Labs should be query-driven. A lens plugin declares supported object kinds, required attributes, commands, sort keys, and dataset projections. The lens receives paginated query results and stable object refs, not SQL rows. Trace Lab and Protocol Lab need streaming datasets because event and packet volume can be much larger than the object graph.

## F-005 Scoring Rule And Triage Pack SDK

Scores MUST remain decomposable into reasons. The existing `score_reasons` table is a good pattern: extend it with plugin namespace, rule ID, rule version, input schema version, confidence, suppression state, and evidence refs. A score should be a materialized view over reason contributions, not an opaque plugin-owned number.

## F-006 Plugin Execution Safety And Permissions

Permissions should be data-scoped. Examples:

- Read artifact bytes by artifact kind or hash.
- Read graph objects by kind.
- Write only declared attribute namespaces.
- Create draft findings but not confirmed findings.
- Emit derived artifacts only under host-managed storage.

The audit trail is part of the data model: every read/write batch should be associated with an analysis run and summarized in diagnostics.

## F-007 Developer Tooling And Test Harness

The SDK test harness should validate manifests, schemas, migrations, and golden `ObjectBatch` outputs without opening the TUI. Fixture projects should include a binary, trace JSONL, crash log, pcap/tshark output, binwalk tree, and prior RevDeck project bundle. Compatibility tests should replay old plugin outputs against newer schemas.

## F-008 Plugin Driven Finding And Report Workflow

Plugins MAY propose draft findings and report sections, but confirmed findings remain analyst-owned. Data model changes:

- `finding_origin`: analyst, plugin_suggestion, imported.
- `suggestion_status`: open, accepted, rejected, superseded.
- `evidence_chain`: ordered evidence links with provenance per link.
- `report_fragment`: plugin-authored section with schema ID, source run, and redaction flags.

Exporters should consume the same stable graph and finding APIs as the TUI. JSON, Markdown, SARIF, and RevDeck bundle exports should include enough provenance to reproduce or challenge each claim.

## Priority Data Decisions

1. Define the v0.9 core object and edge vocabulary before custom plugin object kinds.
2. Add a schema registry for typed attributes, datasets, and report fragments.
3. Add contribution tables so repeated imports and multiple plugins do not overwrite each other's assertions.
4. Make artifact storage content-addressed and keep large blobs outside SQLite.
5. Publish query APIs with predicates, pagination, traversals, and projections, but no direct SQL.
