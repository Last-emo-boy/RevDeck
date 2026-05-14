# System Architect Cross-Cutting Decisions

## Runtime Boundary

RevDeck should use a hybrid-ready architecture with a process protocol as the stable boundary for v0.9. The stable contract is not Rust ABI; it is manifest plus schema-validated request/response envelopes. This supports Rust, Python, Go, and shell-backed external tool adapters without exposing SQLite internals.

Recommended host/guest flow:

1. Host reads `revdeck-plugin.toml`, validates compatibility and permissions.
2. Host computes input digest from artifact refs, plugin version, config, schema version, selected project objects, and declared external files.
3. Host creates an `analysis_run` with status `running`.
4. Host launches the plugin with a job request file or stdin frame and a scoped workspace directory.
5. Plugin emits ordered events: `diagnostic`, `object_upsert`, `edge_upsert`, `score_reason`, `draft_finding`, `report_section`, `artifact_registration`, `progress`, `heartbeat`.
6. Host validates events, buffers a graph delta, checks permissions, then commits in one SQLite transaction.
7. Host finishes the run as `succeeded`, `failed`, or `canceled` with sanitized diagnostics.

The host should support JSONL first for debuggability. MessagePack can be added later for high-volume traces and pcaps after the schema is stable.

## Data Model

Existing tables should remain canonical:

- `artifacts`: binaries and future firmware directories, traces, crash logs, pcaps, memory dumps, and external exports.
- `analysis_runs`: run provenance for native analyzers and plugins.
- `objects`: normalized graph nodes with `kind`, stable key, artifact, display name, address, size, metadata, and source run.
- `edges`: typed relationships with confidence, metadata, and source run.
- `score_reasons`: explainable Function Radar/Triage Board contributions.
- `annotations`, `annotation_evidence`: analyst memory and plugin-draft annotations.
- `findings`, `finding_evidence`: analyst-deliverable findings.

Add plugin-specific tables only where the existing graph does not fit:

- `plugins(id, display_name, current_version, trust_level, installed_at, manifest_json)`.
- `plugin_versions(plugin_id, version, sdk_version, revdeck_compat, manifest_digest, package_digest)`.
- `plugin_permission_grants(plugin_id, project_id, permission, scope_json, granted_at, granted_by)`.
- `plugin_config(plugin_id, project_id, config_json, schema_digest, updated_at)`.
- `plugin_output_events(run_id, seq, event_kind, event_digest, accepted, diagnostic_json)` for replay and debugging.
- `plugin_lens_registrations(plugin_id, lens_id, object_kinds_json, command_schema_json, inspector_schema_json)`.

Avoid plugin-owned arbitrary tables in the first SDK. For F-004 labs that need domain data, prefer object metadata and typed object families such as `trace_event`, `crash`, `protocol_message`, `memory_region`, introduced through core migrations after schema review.

## State Machine

Plugin package state:

`discovered -> manifest_validated -> installed -> disabled|enabled -> update_available -> removed`

Validation failure is terminal for that package version but should not affect other installed versions.

Plugin run state:

`queued -> permission_checked -> starting -> running -> output_validating -> committing -> succeeded`

Failure branches:

- `permission_checked -> denied`
- `starting -> launch_failed`
- `running -> timed_out|crashed|canceled`
- `output_validating -> protocol_failed|schema_failed|policy_failed`
- `committing -> commit_failed`

All terminal states map back into `analysis_runs.status` as `succeeded`, `failed`, or `canceled`, with detailed machine codes in `error_json` and user-safe messages in `diagnostics_json`.

Deterministic re-run state:

`candidate -> input_digest_match -> replay_required|cache_hit -> mismatch_detected|accepted`

A deterministic plugin must emit the same accepted event digest sequence for the same input digest. Non-deterministic plugins must declare why, for example wall-clock sampling or external tool nondeterminism, and their output should be marked lower trust.

## Error Handling

Error envelopes should include `code`, `severity`, `stage`, `recoverable`, `message`, `redacted_detail`, `source_location`, and optional `event_seq`. Stages should extend current `DiagnosticStage` with `manifest`, `permission`, `launch`, `protocol`, `schema_validate`, `policy_validate`, `commit`, `replay`, and `cleanup`.

The host must fail closed:

- Unknown manifest fields are warnings only if the manifest schema allows extension; unknown required fields fail validation.
- Undeclared capability usage fails the run.
- Output for undeclared object kinds, edge kinds, or report sections fails validation.
- Permission requests at runtime that exceed manifest grants fail the run.
- Plugin process crash never corrupts the project because writes are host-buffered.
- Commit conflicts fail the run or degrade to explicit merge diagnostics; they must not silently overwrite analyst annotations or confirmed findings.

External adapter failures should be recoverable by default. For example, a tshark adapter can emit accepted packet metadata and warnings for malformed frames; a corrupt Volatility JSON import can fail only the invalid records if checkpointed import mode is enabled.

## Observability

Minimum metrics:

- `plugin_run_duration_ms`: end-to-end run time by plugin ID, capability, and status.
- `plugin_startup_ms`: process launch plus handshake time.
- `plugin_heartbeat_lag_ms`: time since last heartbeat for long jobs.
- `plugin_protocol_events_total`: accepted and rejected events by event kind.
- `plugin_output_validation_failures_total`: schema, policy, and reference failures.
- `plugin_objects_emitted_total`: nodes emitted by object kind.
- `plugin_edges_emitted_total`: edges emitted by edge kind.
- `plugin_score_reasons_total`: scoring reasons by score kind and plugin.
- `plugin_draft_findings_total`: suggested findings by severity and status.
- `plugin_commit_duration_ms`: buffered graph delta commit time.
- `plugin_timeout_total` and `plugin_crash_total`: reliability counters.
- `plugin_sandbox_denials_total`: denied filesystem, network, process, or secret access.
- `deterministic_replay_mismatch_total`: reproducibility regressions.
- `plugin_output_bytes_total`: stdout/stderr/protocol volume for resource tuning.

Expose a TUI diagnostics lens and CLI commands such as `revdeck plugin list`, `revdeck plugin inspect`, `revdeck plugin runs`, `revdeck plugin replay`, and `revdeck plugin doctor`.

## Configuration Model

Layered configuration should resolve in this order:

1. Built-in defaults from SDK schema.
2. User-global defaults, such as trust prompts and external tool paths.
3. Project-local plugin enablement and config.
4. Per-run CLI/TUI overrides.
5. Environment overrides only for explicitly allowed keys.

Configuration documents should be validated against each plugin's manifest-declared JSON Schema. Store the resolved config digest on every run. Permissions should not be hidden inside arbitrary config; they need first-class grants with scopes:

- `artifact.read`: all, selected artifacts, or path patterns inside project storage.
- `project.read`: object kinds and query limits.
- `project.write`: object families, score reasons, annotations, draft findings, report sections.
- `filesystem.read/write`: scoped directories only.
- `network`: denied by default, optional allowlist.
- `process.spawn`: denied by default, optionally allow declared tools.
- `secrets.read`: denied for initial SDK.

## Integration Pattern

For the current codebase, implement in increments:

- Create SDK schema types in `revdeck-core` or a sibling SDK crate, reusing current `ObjectRef`, `StableObjectKey`, `AnalysisRun`, `ScoreReason`, and `Finding` structures.
- Add `revdeck-plugin-host` for manifest validation, job request creation, process launch, event validation, and transactional commit through `revdeck-db`.
- Extend `revdeck-cli` with plugin commands before deep TUI integration.
- Add a TUI Plugin Runs/Diagnostics lens that reuses the existing three-panel workspace and inspector behavior.
- Prove the contract with first-party plugins: Ghidra/radare2 JSON importer, ASAN crash importer, tshark/pcap adapter, and Function Radar rule pack.

The main architectural risk is custom object extensibility. The safer default is core-owned object families plus metadata extensions. Free-form custom types can be considered after RevDeck has schema migration rules, query indexing rules, and TUI rendering contracts.
