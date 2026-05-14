# P1 Analysis Jobs Context

Source: .workflow/.csv-wave/20260514-design-mature-re-workbench-parity/context.md

Latest completed slice: P0 Responsive Analyze.

Next roadmap item: P1 Pass Status And Jobs.

Scope for this iteration:
- Add a durable `analysis_jobs` table.
- Add repository APIs to insert, update, and list jobs.
- Record native importer pass/job rows for parse, surface, seed, cfg, and triage.
- Add `revdeck jobs <project>` for historical job visibility.
- Defer TUI Jobs lens, cancellation, and rerun control to a later iteration.

Existing patterns:
- Migrations live in numbered SQL files and are wired in `crates/revdeck-db/src/migrations.rs`.
- `AnalysisRunRepository` and `PluginRunRepository` show insert/update/get patterns with RFC3339 times.
- CLI commands in `crates/revdeck-cli/src/main.rs` either print JSON for analysis outputs or compact text for stats.
- Importer already has clean pass boundaries: parse/surface facts, function seed, optional native CFG, and Function Radar scoring.

## Execution result

Completed:
- Added schema migration `0008_analysis_jobs.sql` and bumped schema version to 8.
- Added `AnalysisJobRepository`, `NewAnalysisJob`, `AnalysisJobUpdate`, and `AnalysisJobRecord`.
- Native import now records historical jobs for `parse`, `surface`, `seed`, `linear`, `cfg`, `dataflow`, and `triage`.
- Quick profile records `linear`, `cfg`, and `dataflow` as `skipped`, not failed.
- Added `revdeck jobs <project_dir> [--limit N]` JSON output.
- Extended CLI regression coverage to verify `jobs` after `analyze --profile quick`.
- Documented `revdeck jobs` in README.

Deferred:
- TUI Jobs lens and Cockpit status.
- Cancel/rerun command stubs.
- True async/resumable job execution.

Verification:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
