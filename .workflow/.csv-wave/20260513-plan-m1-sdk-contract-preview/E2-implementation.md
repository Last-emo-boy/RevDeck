# E2 Implementation Exploration

## Scope Read

Inputs read:

- Prior brainstorm report: `.workflow/.csv-wave/20260513-brainstorm-revdeck-plugin-sdk-versatile-reverse/context.md`
- M1 feature specs: `F-001`, `F-002`, `F-006`, `F-007`
- Code paths for CLI, core commands/types, DB repositories/migrations, index import, tests, fixtures, and README.

M1 target from the brainstorm is a local SDK contract preview: manifest validation and inspection, host-mediated ObjectBatch dry-run, process runner audit/diagnostics, and `revdeck plugin test` fixture replay.

## Cargo And Crate Conventions

- Root workspace lists first-party crates under `crates/*` and integration test crates under `tests/*` in `Cargo.toml:2`.
- Shared dependencies are centralized in `[workspace.dependencies]` at `Cargo.toml:24`. Current workspace deps include `clap`, `rusqlite`, `serde`, `serde_json`, `sha2`, `tempfile`, `thiserror`, `time`, `object`, `ratatui`, and `crossterm` at `Cargo.toml:27`.
- Each crate has package metadata inherited from workspace package fields and path dependencies to sibling crates. Example: `revdeck-cli` depends on `revdeck-core`, `revdeck-db`, `revdeck-index`, and `revdeck-tui`.

Planning implications:

- Add any new first-party crates as `crates/revdeck-plugin-sdk` and likely `crates/revdeck-plugin-host`, then add them to root `workspace.members`.
- Add integration coverage as a dedicated workspace test crate, e.g. `tests/plugin-sdk`, matching `tests/commands`, `tests/radar`, and `tests/tui`.
- M1 requires TOML manifest parsing, compatibility range parsing, and possibly config schema validation. `toml`, `semver`, `schemars`, and `jsonschema` are not workspace dependencies today. `semver` appears only transitively in `Cargo.lock`, so the implementation should add explicit workspace deps instead of relying on transitive packages.

## CLI Patterns

- The CLI uses `clap` derive with a top-level `Command` enum in `crates/revdeck-cli/src/main.rs:21`, dispatched directly inside `main`.
- Current commands are `Analyze`, `Init`, `Open`, `Import`, `Index`, `Stats`, `Report`, and `Tui`. `ReportFormat` uses `ValueEnum` at `crates/revdeck-cli/src/main.rs:59`.
- Commands that return machine-readable status use `serde_json::json!` and `println!`, notably `analyze` and `import`.
- Project-opening errors use `anyhow::Context`; index import errors are converted with `ImportError::structured_message()`.

Planning implications:

- Implement `revdeck plugin validate|inspect|test|run --dry-run` as a nested `PluginCommand` enum under a new top-level `Command::Plugin { command: PluginCommand }`.
- Because `main.rs` is already a single large dispatch file, M1 should consider a small CLI module split, e.g. `crates/revdeck-cli/src/plugin.rs`, with handler functions returning `anyhow::Result<()>`. This keeps plugin parsing and rendering testable.
- CLI output for validation/inspection should be stable JSON-first, with human-readable output optional later. This matches existing JSON summaries for imports and structured validation errors for reports.

## Core Type And Validation Patterns

- Stable public enums use `Serialize`, `Deserialize`, `#[serde(rename_all = "snake_case")]`, `as_str`, `Display`, and `FromStr`. Examples include `ObjectKind` in `crates/revdeck-core/src/object.rs:8`, `AnalysisRunStatus` in `crates/revdeck-core/src/analysis.rs:8`, and diagnostic enums in `crates/revdeck-core/src/analysis.rs:108`.
- `StableObjectKey` and `ObjectRef` already provide deterministic identity primitives for object graph data. Key construction normalizes component names/values and rejects invalid keys in `crates/revdeck-core/src/object.rs:369`.
- Export validation provides the closest existing "validation report" model: `ExportValidationReport` has serializable `errors` and `warnings` at `crates/revdeck-core/src/export/mod.rs:26`, and `pre_export_validation` returns either a report or `ExportValidationError` at `crates/revdeck-core/src/export/mod.rs:52`.
- Analysis diagnostics use structured severity, stage, code, message, and recoverable fields via `AnalysisDiagnostic` at `crates/revdeck-core/src/analysis.rs:155`.

Planning implications:

- Put stable SDK structs in `revdeck-plugin-sdk` and derive serde with snake_case naming. Keep `as_str`/`Display`/`FromStr` for capability and permission enums.
- Manifest validation should return a report similar to export validation, not just a single error string. Include normalized manifest digest in the successful result.
- ObjectBatch SDK types should reuse `revdeck_core::ObjectRef` and `StableObjectKey` rather than defining parallel identity primitives.

## DB And Persistence Patterns

- DB access is organized through small repository structs in `crates/revdeck-db/src/repo.rs:37`, including `ArtifactRepository`, `ObjectRepository`, `IndexRepository`, `AnalysisRunRepository`, `RadarRepository`, `MemoryRepository`, and `FindingRepository`.
- Repositories expose explicit `upsert_*`, `list_*`, and `get_*` methods. Object graph writes go through `ObjectRepository::upsert_object` at `crates/revdeck-db/src/repo.rs:214` and `ObjectRepository::upsert_edge` at `crates/revdeck-db/src/repo.rs:287`.
- Migrations are `include_str!` constants with `SCHEMA_VERSION` and are applied in order inside transactions in `crates/revdeck-db/src/migrations.rs:4` and `crates/revdeck-db/src/migrations.rs:41`.
- Projects store SQLite under `.revdeck/project.sqlite` with foreign keys enabled on open/create in `crates/revdeck-db/src/project.rs:5` and `crates/revdeck-db/src/project.rs:20`.

Planning implications:

- Plugin run audit data can initially reuse `analysis_runs` only if the existing four-status lifecycle is sufficient. F-006 requires `discovered -> validated -> installed -> configured -> queued -> starting -> running -> committing -> succeeded | failed | canceled -> superseded`, so a plugin-specific run/state table is likely needed for faithful M1 behavior.
- ObjectBatch dry-run should live in host code, not DB code alone: validate object refs, dangling edges, unknown kinds, permissions, provenance, and digest before calling repo upserts.
- If M1 commits any plugin facts, add a new migration and repository methods instead of direct SQL in CLI or host runner.

## Similar Features To Follow

1. Import lifecycle: `revdeck-index::import_binary` at `crates/revdeck-index/src/lib.rs:146` reads input, creates a pending artifact, starts an analysis run, then routes success/failure to `persist_success` or `persist_failure`.
2. Failure audit: corrupt binary tests assert failed status, diagnostics, `error_json`, and project reopenability in `crates/revdeck-index/src/lib.rs:1375`.
3. Command pipeline: `revdeck-core::commands` parses to AST, resolves against `ObjectGraphQuery`, then mutates in `CommandExecutor`; tests assert ambiguous resolution does not mutate state.
4. Export validation: `pre_export_validation` accumulates structured errors and warnings before rendering, which maps well to manifest and ObjectBatch dry-run diagnostics.
5. Test harness style: integration crates use `tempfile`, repo-root fixture helpers, in-memory SQLite migration helpers, golden markdown output, and `ratatui::TestBackend` render assertions.

## Test And Fixture Patterns

- Unit tests live beside modules for core types and repo internals.
- Integration tests are split by feature under `tests/*` workspace crates. Examples: command pipeline tests in `tests/commands/tests/command_pipeline.rs:32`, export golden tests in `tests/export/tests/export_reports.rs:149`, radar fixture tests in `tests/radar/tests/radar_fixture.rs:20`, and TUI persistence tests in `tests/tui/tests/tui_workspace.rs:271`.
- Binary fixtures live under `fixtures/binaries`; tests compute repo root from `CARGO_MANIFEST_DIR` and use `tempfile::tempdir()` for project directories.
- There are workspace deps for `assert_cmd` and `predicates`, but no current CLI binary integration tests use them.

Planning implications:

- Add fixture directories for plugin work, e.g. `fixtures/plugins/manifest-valid`, `fixtures/plugins/manifest-invalid`, and `fixtures/plugin-batches`.
- Add tests for valid/invalid TOML, permission denial, malformed ObjectBatch, dangling edge rejection, idempotent dry-run digest, and deterministic fixture replay.
- Because the CLI crate is currently only a bin, either use `assert_cmd` for `revdeck plugin ...` integration tests or move plugin command handlers into a module with testable functions.

## Risks And Blockers

- No TOML parser or direct semver/config schema validation dependency is currently declared in the workspace.
- There is no existing process runner, sandbox, permission evaluator, resource limit model, or redaction helper. Search did not find `std::process` runner usage in the product code.
- `persist_success` performs many DB writes and only migrations currently use explicit transactions. ObjectBatch commit must avoid partial mutation by validating before writes or by adding a transaction boundary.
- Existing `AnalysisRunStatus` is too narrow for the F-006 plugin state machine. Extending it could affect existing DB parsing and tests; a dedicated plugin-run state is safer.
- Direct SQLite writes by plugins conflict with the product decision. Keep SQL private to host repositories and expose only SDK/host validation APIs.

## Recommended Implementation Shape For M1

- `crates/revdeck-plugin-sdk`: manifest model, capability/permission enums, ObjectBatch DTOs, normalized digest helpers, validation reports, and JSON/TOML parsing helpers.
- `crates/revdeck-plugin-host`: permission evaluator, ObjectBatch dry-run validator, fixture replay harness, process-runner skeleton with sanitized diagnostics, and optional repository integration.
- `crates/revdeck-cli/src/plugin.rs`: CLI rendering and command handlers for `validate`, `inspect`, `test`, and `run --dry-run`.
- `tests/plugin-sdk`: integration tests and fixture replay covering F-001, F-002, F-006, and minimum F-007.

Keep the first plan slice focused on validation and dry-run. Defer marketplace, install flow, custom UI registration, and direct commit of plugin facts unless M1 explicitly adds the needed migration and atomic commit path.
