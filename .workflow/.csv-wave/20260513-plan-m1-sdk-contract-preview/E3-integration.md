# E3 Integration Exploration

Scope: integration points for M1 SDK Contract Preview (`F-001`, `F-002`, `F-006`, minimum `F-007`). This exploration read the prior brainstorm report and M1 feature specs, then inspected the Rust workspace without modifying source code.

## Prior Context

The brainstorm report recommends a local SDK preview before marketplace work. M1 exit criteria are concrete:

- `revdeck-plugin.toml` validates.
- `revdeck plugin inspect` shows capabilities and permissions.
- ObjectBatch dry-run validates graph deltas.
- A process plugin runner records plugin runs and sanitized diagnostics.
- `revdeck plugin test` runs fixture replay and permission-denial tests.

The relevant specs tighten that into a host-owned contract:

- F-001: manifest is the public trust and compatibility contract; plugins must not request direct SQLite access.
- F-002: ObjectBatch graph deltas are host-mediated and keyed by stable object refs.
- F-006: plugin execution defaults to least privilege and must be audited.
- F-007: the harness compares normalized graph bundles and permission behavior, not private SQLite snapshots.

## Current Integration Shape

RevDeck is a small Rust workspace with product crates under `crates/revdeck-*` and integration-test crates under `tests/*`. There is no existing plugin, ObjectBatch, process runner, or sandbox implementation; `rg` only found plugin references in planning docs.

### CLI Entry Point

`crates/revdeck-cli/src/main.rs` is a flat `clap` command enum and single dispatcher:

- `Command` starts at `crates/revdeck-cli/src/main.rs:21`.
- Dispatch starts at `crates/revdeck-cli/src/main.rs:66`.
- `Analyze` and `Import` already print JSON-like status objects including `status`, `artifact`, `analysis_run`, and count summaries.
- `ReportFormat` uses `ValueEnum` at `crates/revdeck-cli/src/main.rs:58`.

M1 should add a nested `PluginCommand` under `Command::Plugin`, then delegate implementation to a small CLI module or directly to `revdeck-plugin-host`. Keeping `main.rs` as a thin dispatcher matches the existing pattern, but adding all plugin logic inline would make the current single file too broad.

Practical command mapping:

- `revdeck plugin validate <path>`: SDK-only manifest parse/validation; no project required.
- `revdeck plugin inspect <path>`: SDK manifest normalization plus capabilities/permissions/digest summary.
- `revdeck plugin test <path>`: host harness entry point; runs fixture replay and permission-denial tests.
- ObjectBatch dry-run can be exposed either as `revdeck plugin run --dry-run ...` per F-006/F-007 or as a hidden/internal harness step for M1. If the public CLI includes it, route through host validation and do not open mutation repositories.

### SDK Contract Touch Points

`crates/revdeck-core/src/object.rs` is the existing stable identity source:

- `ObjectKind` and `EdgeKind` use `serde(rename_all = "snake_case")`.
- `StableObjectKey` and `ObjectRef` are public and already re-exported from `revdeck-core`.
- Key builders normalize components and reject backslashes, which matters for Windows-compatible replay.

ObjectBatch SDK structs should reuse these types instead of inventing parallel refs. Keep the public plugin SDK free of `rusqlite`; the host crate should bridge SDK facts into `revdeck-db` repositories.

The structured validation model in `crates/revdeck-core/src/export/mod.rs` is the closest existing pattern: `pre_export_validation` accumulates serializable errors and warnings before returning a typed error. Manifest and ObjectBatch validators should follow the same report shape so CLI output and harness assertions can be stable.

### DB And Analysis Run Integration

The current audit anchor is `analysis_runs` from `crates/revdeck-db/migrations/0001_foundation.sql`. It records:

- `artifact_key`
- `analyzer_id`
- `analyzer_version`
- `input_hash`
- `status`
- `diagnostics_json`
- `error_json`
- `recoverable`

`AnalysisRunStatus` only supports `running`, `succeeded`, `failed`, and `canceled` in `crates/revdeck-core/src/analysis.rs:8`. The richer plugin lifecycle from F-006 (`validated`, `configured`, `queued`, `starting`, `committing`, `superseded`, etc.) should not be forced into this enum for M1. A separate `plugin_runs` table keyed to `analysis_run_id` is cleaner:

- plugin id/version
- manifest digest
- input digest
- config digest
- requested/granted permissions
- current plugin lifecycle state
- accepted/rejected object and edge counts
- commit result
- sanitized diagnostics JSON

This keeps current analysis status semantics intact and lets future TUI chips/report surfaces query plugin state directly.

Relevant DB files:

- `crates/revdeck-db/src/repo.rs:1488`: `AnalysisRunRepository::start`.
- `crates/revdeck-db/src/repo.rs:1513`: `AnalysisRunRepository::finish`.
- `crates/revdeck-db/src/repo.rs:214`: `ObjectRepository::upsert_object`.
- `crates/revdeck-db/src/repo.rs:287`: `ObjectRepository::upsert_edge`.
- `crates/revdeck-db/src/repo.rs:332`: `IndexRepository::remove_indexed_facts_for_artifact`.
- `crates/revdeck-db/src/project.rs:42`: `ProjectDatabase::connection_mut`.

### ObjectBatch Dry-Run And Commit Path

`revdeck-index::import_binary` is the closest orchestration pattern:

- registers artifact/object
- starts an analysis run
- persists objects/edges with `source_run_id`
- serializes diagnostics into `analysis_runs`
- marks run success/failure

However, `persist_success` writes incrementally through repositories without an explicit transaction. That is acceptable for current native import but not for plugin ObjectBatch. F-002 and F-006 require rejected batches and failures to be non-mutating.

Planning implication:

1. Implement `ObjectBatchValidator` first as a pure function over SDK data plus an optional DB lookup interface.
2. Implement dry-run summary that never constructs mutation repositories.
3. Implement commit as validate-then-transaction:
   - start an `analysis_runs` row outside the mutation transaction so failed attempts remain audited;
   - run final validation;
   - open a transaction from `ProjectDatabase::connection_mut`;
   - upsert accepted objects/edges with `source_run_id`;
   - commit or roll back;
   - finish the analysis run with sanitized diagnostics.

Edge validation must reject dangling sources/targets unless the referenced objects already exist in DB or are included earlier in the same batch. Unknown `ObjectKind`/`EdgeKind` should fail during SDK deserialization/validation.

### Process Host Skeleton

No code currently uses `std::process::Command` for plugin-like execution. `crates/revdeck-plugin-host` should own:

- manifest permission evaluation;
- fixture runner;
- process launch skeleton;
- stdout/stderr capture and redaction;
- timeout/kill behavior;
- ObjectBatch dry-run and commit orchestration;
- plugin run audit writes.

For M1, "sandbox" should be treated as a contract and harness behavior, not a full OS sandbox. The host can deny requested capabilities before process launch, pass only minimal environment/config, and validate plugin protocol output. Permission-denial tests can use fake plugins/protocol fixtures that attempt denied operations, while the host asserts no DB mutation and sanitized diagnostics.

Windows-specific planning:

- Launch binaries directly, not through `cmd /c` or shell wrappers.
- Close stdin when done and bound stdout/stderr collection.
- Use timeout + child kill semantics that work on Windows.
- Do not assume POSIX signals, executable bits, `/tmp`, or path separators.

### TUI, Diagnostics, And Report Surfaces

`crates/revdeck-tui/src/lib.rs` already loads objects, relations, scores, findings, and latest analysis status into `WorkspaceSnapshot::load_from_project` (`crates/revdeck-tui/src/lib.rs:96`). If plugin ObjectBatch commits use existing core object/edge kinds, basic graph navigation and inspector backlinks will work through existing queries.

Future plugin chips and diagnostics need a new read path. Current `IndexRepository::latest_analysis_run` is artifact-wide and ordered by newest row (`crates/revdeck-db/src/repo.rs:528`). If plugin runs use `analysis_runs` directly without a `plugin_runs` table or analyzer filtering, the overview could show a plugin execution as the latest artifact analysis status. Avoid relying on this query for plugin UI state.

Reports currently export findings only through `FindingRepository::export_context` and `render_json`/`render_markdown`. F-008 is deferred, so M1 should avoid report behavior changes except ensuring committed plugin evidence can be linked to analyst-created findings later.

### Test Harness Integration

Existing test layout favors separate workspace test crates:

- `tests/commands` covers command parser/resolver behavior.
- `tests/tui` covers reducer-first TUI workflows and export persistence.
- `tests/export`, `tests/radar`, `tests/foundation`, etc. cover feature slices.

The workspace already declares `assert_cmd` and `predicates`, but current tests do not use binary-level CLI assertions. M1 should add `tests/plugin-sdk` or `tests/plugin` with fixtures for:

- valid and invalid `revdeck-plugin.toml`;
- manifest inspect output;
- ObjectBatch dry-run accepted/rejected summaries;
- deterministic replay against normalized graph summaries;
- permission-denial fixtures;
- process crash/timeout/malformed output;
- no mutation on failed dry-run or failed process.

If binary CLI tests are needed, use `assert_cmd` in the new integration crate rather than coupling plugin tests to the TUI reducer tests.

## File Ownership For The Plan

Suggested ownership boundaries:

- `Cargo.toml`: add workspace members and explicit dependencies (`toml` or `toml_edit`, explicit `semver`; schema dependency if chosen).
- `crates/revdeck-plugin-sdk/*`: public manifest, permissions, ObjectBatch, protocol/fixture data contracts, validation reports. No DB access.
- `crates/revdeck-plugin-host/*`: manifest loading, permission evaluator, dry-run validator bridge, process runner skeleton, diagnostics redaction, plugin run audit, fixture harness.
- `crates/revdeck-db/migrations/0005_plugin_runs.sql`: plugin audit table.
- `crates/revdeck-db/src/migrations.rs`: schema version and migration registration.
- `crates/revdeck-db/src/repo.rs`: `PluginRunRepository` and query helpers.
- `crates/revdeck-cli/src/main.rs` plus optionally `crates/revdeck-cli/src/plugin.rs`: `revdeck plugin validate|inspect|test` wiring.
- `tests/plugin-sdk/*` or `tests/plugin/*`: fixtures and conformance tests.

Avoid changing `revdeck-tui` or report rendering for M1 unless the final plan explicitly adds read-only plugin state chips. Basic visibility of plugin-created objects should come from existing graph queries after host-mediated commit.

## Planning Implications

Recommended dependency order:

1. SDK contracts and validation reports: manifest, permissions, ObjectBatch types, deterministic digest helpers, fixtures.
2. DB audit support: migration and repository for plugin run metadata, without changing current `AnalysisRunStatus`.
3. Host dry-run and commit bridge: validate-only path first, then transaction-backed commit path.
4. Process runner skeleton and permission evaluator: direct process launch, bounded output, sanitized diagnostics, denied-by-default behavior.
5. CLI integration: thin `plugin` subcommands calling SDK/host APIs.
6. Harness/tests: golden manifests, ObjectBatch dry-run, deterministic replay, permission denial, failed process no-mutation checks.

Do not split tasks per file. The natural units are SDK contract, DB/audit integration, host runtime/dry-run, CLI surface, and conformance tests.

## Risks

- `latest_analysis_run` pollution: plugin runs can become the latest artifact run and confuse TUI overview unless plugin state is separated or existing queries are filtered.
- Partial mutation: current import persistence is incremental; ObjectBatch commit needs explicit transaction tests.
- Dependency ambiguity: `semver` appears only transitively in `Cargo.lock`; TOML/schema validation dependencies are not declared in the workspace.
- Sandbox gap: M1 can enforce permissions at host/protocol level, but should not imply a strong OS sandbox.
- Windows process behavior: timeout, env stripping, path normalization, and direct process launching need explicit tests.
- Deterministic replay: normalize ordering, timestamps, digests, diagnostics, and graph summaries; do not compare private SQLite snapshots.
