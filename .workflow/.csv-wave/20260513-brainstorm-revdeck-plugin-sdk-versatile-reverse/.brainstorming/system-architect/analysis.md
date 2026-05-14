# System Architect Analysis

## Summary

RevDeck should make the first plugin SDK a host-mediated extension system, not an in-process ABI promise. The current Rust workspace already has the right nucleus: `revdeck-core` owns stable `ObjectRef` and schema types, `revdeck-db` owns SQLite repositories and migrations, `revdeck-index` creates native analysis runs, and `revdeck-tui` consumes query/view models. The plugin layer should sit between external tools and the repository layer through validated envelopes, so plugins never write private SQLite tables directly.

The v0.9 architecture should prefer process-based plugins over dynamic libraries. A plugin executable receives a manifest-approved job request, reads allowed artifact/project snapshots, emits JSONL or MessagePack-framed result events, and exits. The host validates every emitted object, edge, score, diagnostic, draft finding, and report section before committing one transaction under a recorded `analysis_run`. Native Rust helpers can be provided by the SDK, but the host/guest contract should remain language-neutral.

## Feature Architecture

F-001 `plugin-manifest-and-capability-model`: Define `revdeck-plugin.toml` with `id`, `version`, `sdk_version`, `revdeck_compat`, `capabilities`, `permissions`, `commands`, `inputs`, `outputs`, `config_schema`, `determinism`, and `provenance`. The manifest MUST be validated at install and again before run. Capability flags should map to host services: `importer`, `adapter`, `analyzer`, `scorer`, `lens`, `exporter`, `action`, `rule_pack`.

F-002 `stable-schema-and-object-graph-sdk`: Promote current `ObjectRef`, `StableObjectKey`, `ObjectKind`, `EdgeKind`, `AnalysisRun`, `ScoreReason`, `Finding`, and `FindingEvidence` into an SDK crate or generated schema package. Plugin output MUST use stable IDs and MUST include `source_run_id`, plugin ID, plugin version, source artifact, input digest, and deterministic ordering.

F-003 `importer-and-adapter-sdk`: Treat adapters as translators from Ghidra/radare2/rizin, Frida/QEMU traces, ASAN logs, Volatility JSON, binwalk trees, pcap/tshark, and generic JSONL into RevDeck envelopes. Adapters SHOULD produce normalized graph deltas plus diagnostics rather than custom tables first.

F-004 `specialized-lab-extension-points`: Lens plugins should start as declarative lens contributions: query, row model, inspector sections, commands, navigation targets, and selection behavior. Fully custom drawing should come after stable object/query APIs.

F-005 `scoring-rule-and-triage-pack-sdk`: Scorers should emit `ScoreReason` records, not opaque scores. Host aggregation computes final Function Radar/Triage Board ordering from signed reasons, weights, confidence, and provenance.

F-006 `plugin-execution-safety-and-permissions`: Default to no network, read-only project snapshot, bounded artifact access, no external process launch, timeout, stdout/stderr limits, and one transactional write scope. Broader scopes require explicit manifest permissions and per-project approval.

F-007 `developer-tooling-and-test-harness`: Ship schema validators, fixture projects, golden output tests, deterministic replay, and `revdeck plugin test`. CI should validate manifests, permissions, schemas, output ordering, and compatibility ranges.

F-008 `plugin-driven-finding-and-report-workflow`: Plugins may propose draft findings and report sections. Analyst-confirmed findings remain distinct from plugin suggestions in DB state, TUI labels, and exports.

## Required Models

Data model: add `plugins`, `plugin_versions`, `plugin_permissions`, `plugin_runs` as an extension of `analysis_runs`, `plugin_config`, `plugin_diagnostics`, `plugin_output_events`, and optional `object_extensions`. Existing `objects`, `edges`, `score_reasons`, `annotations`, `findings`, and `finding_evidence` remain the canonical graph.

State machine: `discovered -> validated -> installed -> configured -> queued -> starting -> running -> committing -> succeeded|failed|canceled -> superseded`. A failed run must leave diagnostics and no partial commits unless the job explicitly uses checkpointed import mode.

Error handling: separate manifest validation errors, permission denial, protocol errors, schema validation errors, plugin crash/timeout, deterministic mismatch, commit conflicts, and analyst-canceled runs. All failures should attach sanitized diagnostics to the run.

Observability: track `plugin_run_duration_ms`, `plugin_startup_ms`, `plugin_protocol_events_total`, `plugin_output_validation_failures_total`, `plugin_objects_emitted_total`, `plugin_edges_emitted_total`, `plugin_diagnostics_total`, `plugin_bytes_read_total`, `plugin_stdout_stderr_bytes_total`, `plugin_timeout_total`, `plugin_commit_duration_ms`, and `deterministic_replay_mismatch_total`.

Configuration model: support user-global trust defaults, project-local plugin enablement, per-plugin config validated by JSON Schema, permission grants, resource limits, external tool paths, network allowlist, artifact read scopes, output redaction policy, and deterministic-run mode.

## Architectural Decision

The first implementation should add a `revdeck-plugin-sdk` crate plus host runtime inside a new `revdeck-plugin-host` crate, but persist only through `revdeck-db` repositories. This keeps the current Binary Triage loop intact while making plugin runs first-class, auditable, deterministic contributors to the same object graph.
