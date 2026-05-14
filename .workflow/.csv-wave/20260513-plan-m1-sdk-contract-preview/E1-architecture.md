# E1 Architecture Exploration -- M1 SDK Contract Preview

## Scope Read

Prior context recommends a local SDK preview before marketplace work. M1 covers:

- F-001: validate `revdeck-plugin.toml`, inspect capabilities/permissions/provenance.
- F-002: stable ObjectBatch graph deltas with host-mediated commits and dry-run validation.
- F-006: least-privilege process runner skeleton, permission denial, sanitized diagnostics, audited runs.
- F-007: minimal `revdeck plugin test` fixture replay and permission-denial tooling.

## Current Architecture

RevDeck is a Rust Cargo workspace (`Cargo.toml:1`) with five product crates and separate integration-test crates:

- `crates/revdeck-core`: domain contracts and pure logic. It exports `ObjectKind`, `EdgeKind`, `ObjectRef`, `StableObjectKey`, analysis run types, query traits, command parser/resolver/executor, radar scoring, findings/export, and view models (`crates/revdeck-core/src/lib.rs:1`).
- `crates/revdeck-db`: SQLite project lifecycle, migrations, repositories, and query adapters (`crates/revdeck-db/src/lib.rs:1`). It depends on `revdeck-core`.
- `crates/revdeck-index`: native binary importer/analyzer and Function Radar scoring orchestration (`crates/revdeck-index/src/lib.rs:146`). It depends on `revdeck-core` and `revdeck-db`.
- `crates/revdeck-cli`: clap-based executable and top-level command orchestration (`crates/revdeck-cli/src/main.rs:20`). It depends on core/db/index/tui.
- `crates/revdeck-tui`: Ratatui shell and workspace rendering. It loads project snapshots via DB repositories and core view models (`crates/revdeck-tui/src/lib.rs:99`, `crates/revdeck-tui/src/lib.rs:1089`).

Current dependency direction:

```text
revdeck-core
  <- revdeck-db
  <- revdeck-index <- revdeck-cli
  <- revdeck-tui   <- revdeck-cli
```

This shape should be preserved. New SDK contracts should not depend on SQLite or CLI. Host execution may depend on DB, but plugins should only see SDK schemas.

## Existing Object/Run Model

`revdeck-core` already has most of the object identity foundation that M1 needs:

- `ObjectKind` and `EdgeKind` are stable serde enums with snake_case wire names (`crates/revdeck-core/src/object.rs:8`, `crates/revdeck-core/src/object.rs:78`).
- `StableObjectKey` normalizes path-like components, forbids backslashes, and has helpers for artifact/section/symbol/function/string/import/edge/xref/score/annotation/finding (`crates/revdeck-core/src/object.rs:149`).
- `ObjectRef` serializes as `{ kind, key }` and string-parses as `<kind>:<stable-key>` (`crates/revdeck-core/src/object.rs:326`).
- `AnalysisRunStatus`, `NewAnalysisRun`, `AnalysisRun`, diagnostics, and boundary confidence are in core (`crates/revdeck-core/src/analysis.rs:8`, `crates/revdeck-core/src/analysis.rs:51`).

`revdeck-db` persists provenance through `analysis_runs`, `objects.source_run_id`, `edges.source_run_id`, and JSON diagnostics/metadata:

- Base tables are in migration 0001: `analysis_runs` (`crates/revdeck-db/migrations/0001_foundation.sql:20`), `objects` (`crates/revdeck-db/migrations/0001_foundation.sql:37`), and `edges` (`crates/revdeck-db/migrations/0001_foundation.sql:54`).
- Current schema version is 4 (`crates/revdeck-db/src/migrations.rs:4`).
- `AnalysisRunRepository::start` and `finish` are the existing run-state write API (`crates/revdeck-db/src/repo.rs:1495`, `crates/revdeck-db/src/repo.rs:1520`).
- `ObjectRepository::upsert_object` and `upsert_edge` are generic enough for a host-mediated ObjectBatch commit path (`crates/revdeck-db/src/repo.rs:214`, `crates/revdeck-db/src/repo.rs:287`).
- `IndexRepository::remove_indexed_facts_for_artifact` is importer-specific and should not be reused blindly for plugins because it deletes all indexed facts for an artifact kind set (`crates/revdeck-db/src/repo.rs:332`).

## Existing Data Flow Pattern

`revdeck-index::import_binary` is the strongest implementation reference for M1 host commit flow:

1. Read external artifact bytes and compute digest (`crates/revdeck-index/src/lib.rs:146`).
2. Register artifact + artifact object before parsing (`crates/revdeck-index/src/lib.rs:160` through `crates/revdeck-index/src/lib.rs:193`).
3. Start an `analysis_runs` row with analyzer id/version/input hash (`crates/revdeck-index/src/lib.rs:195`).
4. On success, remove prior indexed facts, upsert artifact/object/kind tables, add edges, serialize diagnostics, and finish run succeeded (`crates/revdeck-index/src/lib.rs:236` through `crates/revdeck-index/src/lib.rs:500`).
5. On parse failure, keep the project reopenable, finish the run failed, and store structured diagnostics (`crates/revdeck-index/src/lib.rs:542` through `crates/revdeck-index/src/lib.rs:589`).
6. Function Radar runs as a separate analyzer run over existing DB facts (`crates/revdeck-index/src/lib.rs:504`).

M1 should copy the orchestration pattern but insert an ObjectBatch validation phase before any DB mutation. Dry-run should stop before `ObjectRepository`/`IndexRepository` writes and return a normalized summary plus rejected events.

Recommended M1 data flow:

```text
CLI plugin command
  -> revdeck-plugin-host
      -> revdeck-plugin-sdk manifest parser/validator
      -> permission planner + input digest/config digest
      -> optional process runner skeleton
      -> ObjectBatch parser
      -> ObjectBatch dry-run validator
      -> PluginRun audit result
  -> revdeck-db repositories only through host commit/dry-run APIs
```

## Recommended Crate Placement

Add two workspace crates:

- `crates/revdeck-plugin-sdk`
  - Owns public wire contracts: manifest structs, capability/permission enums, ObjectBatch types, protocol diagnostics, normalized manifest digest.
  - Depends on `serde`, `serde_json`, `thiserror`, `sha2`, `time`, and likely new workspace deps `toml` and `semver`.
  - Should avoid `revdeck-db`, `rusqlite`, `revdeck-cli`, and `revdeck-tui`.
  - May depend on `revdeck-core` only if ObjectBatch reuses `ObjectKind`, `EdgeKind`, and `ObjectRef`. This avoids duplicate stable identity definitions. If the public SDK must stay smaller/language-neutral later, define SDK wire mirrors and conversion functions, but that is extra M1 complexity.

- `crates/revdeck-plugin-host`
  - Owns host-side validation, dry-run, permission checks, process runner skeleton, diagnostics sanitization, run audit summaries, and optional DB commit adapter.
  - Depends on `revdeck-plugin-sdk`, `revdeck-core`, `revdeck-db`, `serde_json`, `sha2`, `time`, `thiserror`.
  - Should not depend on `revdeck-cli` or `revdeck-tui`.
  - Should expose narrow APIs for CLI: `validate_manifest`, `inspect_manifest`, `dry_run_object_batch`, `test_plugin_fixture`, and a runner skeleton that can be expanded later.

Then update:

- `Cargo.toml` workspace members and workspace dependencies.
- `crates/revdeck-cli/Cargo.toml` to depend on `revdeck-plugin-host`.
- `crates/revdeck-cli/src/main.rs` to add a nested `plugin` subcommand with `validate`, `inspect`, `dry-run`/`run --dry-run`, and `test`.
- `tests/plugin-sdk` as an integration-test crate for manifest fixtures, ObjectBatch dry-run, CLI command behavior, and permission-denial skeletons.

Avoid placing SDK schemas in `revdeck-index`; that crate is native binary importer-specific. Avoid placing host logic directly in CLI; CLI should remain an orchestration layer.

## DB and Migration Planning

M1 can mostly use the existing `analysis_runs` table for audit records:

- Use `analyzer_id = plugin:<manifest.id>` or a stable equivalent.
- Use `analyzer_version = manifest.version`.
- Use `input_hash` for input digest; add manifest/config digests inside `diagnostics_json` until a first-class plugin_runs table is necessary.

However, F-006 wants audited fields that do not fit cleanly as queryable columns: manifest digest, config digest, permissions, timing, accepted output counts, commit result, sanitized diagnostics. For M1, two options are viable:

1. No new DB migration for preview: store a structured JSON object in `analysis_runs.diagnostics_json` and `error_json`. Fastest and compatible with current schema.
2. Add `plugin_runs` in migration 0005 for queryable plugin run state. More durable for UI chips and later plugin state machine, but larger scope.

Planning implication: keep M1 minimal by using `analysis_runs` JSON first unless integration/risk exploration identifies a hard UI/query need. The planned state machine in F-006 has more states than current `AnalysisRunStatus` (`running/succeeded/failed/canceled`), so a full plugin lifecycle table should be deferred or explicitly scoped.

ObjectBatch commit should not write direct SQL. The host should convert accepted batch facts into:

- `StoredObject` via `ObjectRepository::upsert_object`.
- `StoredEdge` via `ObjectRepository::upsert_edge`.
- Existing kind tables only for known core families (`sections`, `symbols`, `functions`, `strings`, `imports`, `xrefs`, `score_reasons`) when M1 supports them.
- Typed attributes/datasets should initially live in object/edge `metadata_json` or be validation-only. Adding first-class typed-attribute tables is a separate schema decision.

Dry-run should validate:

- Known object/edge kinds through `ObjectKind`/`EdgeKind` parsing.
- Stable key validity via `StableObjectKey::new` / `ObjectRef` parsing.
- Dangling edges within batch plus optional existing DB lookup through `ObjectQueryRepository`.
- Duplicate object keys and duplicate edge keys.
- Confidence ranges and required provenance fields.

## CLI Integration

Current CLI uses a flat `Command` enum and a single `match` in `main` (`crates/revdeck-cli/src/main.rs:20`, `crates/revdeck-cli/src/main.rs:67`). M1 should follow this style with a nested clap subcommand:

```text
revdeck plugin validate <path>
revdeck plugin inspect <path>
revdeck plugin dry-run <project_dir> <batch_path>
revdeck plugin run --dry-run <project_dir> <manifest_or_id>
revdeck plugin test <path>
```

CLI output conventions:

- Existing import/analyze commands print JSON summaries for machine-readable outcomes (`crates/revdeck-cli/src/main.rs:86`, `crates/revdeck-cli/src/main.rs:158`).
- Existing failed import uses `anyhow::bail!` with JSON diagnostics (`crates/revdeck-cli/src/main.rs:102`, `crates/revdeck-cli/src/main.rs:146`).
- `stats` prints a compact text line (`crates/revdeck-cli/src/main.rs:184`).

Planning implication: plugin `validate`, `dry-run`, and `test` should prefer JSON summaries for conformance tooling. `inspect` can be human-readable by default, but should consider a `--json` flag if implementation scope allows.

## Test Architecture

Existing integration tests are workspace crates under `tests/*`, each with its own `Cargo.toml` and narrow dependencies (`Cargo.toml:8` through `Cargo.toml:14`). M1 should add `tests/plugin-sdk` rather than overloading existing tests.

Useful existing patterns:

- Foundation tests create/reopen projects, seed DB repositories, and assert deterministic refs (`tests/foundation/tests/foundation.rs:9`).
- Radar tests run full import fixtures and validate view-model evidence (`tests/radar/tests/radar_fixture.rs:16`).
- TUI tests use reducer-first state tests and Ratatui `TestBackend` snapshots (`tests/tui/tests/tui_workspace.rs:20`).

Recommended new fixtures:

- `fixtures/plugins/valid/revdeck-plugin.toml`
- `fixtures/plugins/invalid/*.toml`
- `fixtures/plugins/object-batches/*.json`
- `fixtures/plugins/fake-process/*` for permission-denial skeletons where feasible.

## Risks and Planning Implications

- Public SDK boundary risk: reusing `revdeck-core::ObjectKind` in `revdeck-plugin-sdk` is pragmatic, but it makes object kind additions part of the public contract. Add schema version fields and compatibility tests from the start.
- DB mutation risk: current repositories perform upserts directly. ObjectBatch dry-run must be separate from commit and must not call upsert functions.
- Deletion/idempotency risk: `remove_indexed_facts_for_artifact` is too broad for plugins and can delete native facts or other plugin facts. M1 should avoid plugin replace semantics or scope replacement by run/plugin metadata only after designing it.
- Audit model risk: existing `AnalysisRunStatus` is too coarse for the full F-006 state machine. Keep M1 audit as JSON diagnostics or explicitly add a small `plugin_runs` table if UI state chips become required.
- Dependency risk: workspace lacks first-class `toml` and `jsonschema` deps. `semver` appears only transitively in `Cargo.lock`; manifest compatibility should add explicit workspace deps.
- Process safety risk: Rust standard library alone can spawn processes but does not sandbox filesystem/network/environment. M1 should label this as a safety skeleton with denial tests, not claim OS-level sandboxing.
- Windows behavior risk: process timeout, environment stripping, path redaction, and child cleanup need targeted tests because the workspace runs on Windows.

## Suggested Task Boundaries For Wave 2

1. SDK crate and fixtures: manifest structs/validation, ObjectBatch wire types, stable digest, unit tests.
2. Host crate: dry-run validator, permission model, sanitized diagnostics, analysis-run audit adapter, process-runner skeleton.
3. CLI and conformance tests: nested `plugin` commands, JSON outputs, `tests/plugin-sdk`, fixtures.

These can be two or three feature-level tasks. Keep DB schema changes optional unless a planner chooses a dedicated `plugin_runs` migration.
