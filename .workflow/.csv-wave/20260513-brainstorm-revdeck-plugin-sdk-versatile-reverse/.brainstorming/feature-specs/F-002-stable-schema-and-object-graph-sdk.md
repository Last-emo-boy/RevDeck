# F-002 Stable Schema And Object Graph SDK

## Purpose

Expose a stable, host-mediated data contract for plugin-produced evidence while keeping RevDeck's private SQLite schema free to evolve.

## User Value

External evidence becomes navigable and reportable inside one project: functions, strings, imports, trace events, crashes, protocol messages, firmware files, notes, scores, and findings share stable object refs and provenance.

## Requirements

- Plugins MUST submit ObjectBatch graph deltas through host APIs.
- Object identity MUST use stable keys, not transient row IDs.
- Plugin-created facts MUST carry plugin ID, version, run ID, schema version, source artifact, timestamp, and confidence where applicable.
- RevDeck SHOULD support typed attributes and host-managed datasets before arbitrary custom object kinds.
- Direct SQL writes MUST NOT be part of the supported SDK.

## SDK/Data Contracts

Core SDK types:

- `ObjectRef { kind, stable_key }`
- `ArtifactRef { object_ref, content_hash, format, storage_uri }`
- `ObjectFact { object_ref, display_name, address, size, attributes }`
- `EdgeFact { source, target, kind, confidence, metadata }`
- `TypedAttribute { subject, namespace, schema_id, key, value }`
- `DatasetRef { namespace, schema_id, storage_uri, index_hints }`
- `AnalysisRunRef { id, plugin_id, plugin_version, input_digest, config_digest }`
- `EvidenceLink { subject, evidence, role, order, note }`

## TUI/CLI Affordances

- Inspector shows plugin attributes under bounded provider sections.
- Local graph views can traverse plugin-created edges after host validation.
- `revdeck plugin dry-run` prints ObjectBatch summary and rejected events without mutating the project.

## Test Strategy

- Deterministic object-key tests.
- Rejected dangling edge and unknown kind tests.
- Idempotent rerun tests.
- Rollback on partial batch failure.
- Golden normalized graph bundles instead of raw SQLite snapshots.

## Rollout Notes

Start with object families already implied by RevDeck v0.1, then add Trace/Crash/Protocol/Firmware/Memory families as SDK schemas mature.
