# Responsive Analyze Profile Context

Source: .workflow/.csv-wave/20260514-design-mature-re-workbench-parity/context.md

Latest recommended slice: P0 Responsive Analyze.

Existing patterns found:
- crates/revdeck-cli/src/main.rs uses clap ValueEnum for ReportFormat and JSON output for analyze/import.
- crates/revdeck-index/src/lib.rs routes all binary ingestion through ImportOptions -> import_binary -> parse_binary -> persist_success.
- Analysis diagnostics use AnalysisDiagnostic::new with stable code/stage/severity and are serialized through AnalysisSummary.
- Existing tests construct ImportOptions in revdeck-index unit tests, radar tests, and TUI tests.

Implementation plan:
1. Add AnalysisProfile enum and default balanced behavior in revdeck-index.
2. Thread profile through ImportOptions and parse_binary.
3. For quick profile, skip native CFG persistence and emit pass_skipped_by_profile warning.
4. Add CLI --profile quick|balanced|deep for analyze/import and include profile in JSON output.
5. Update README and add tests.

## Execution result

Completed:
- Added `AnalysisProfile` with `quick`, `balanced`, and `deep`.
- Kept `balanced` as the default ImportOptions behavior.
- Made `quick` skip native CFG, instruction persistence, and dataflow enrichment while retaining sections, imports, strings, function seeds, and baseline xrefs.
- Emitted recoverable `pass_skipped_by_profile` diagnostics for quick profile.
- Added `--profile quick|balanced|deep` to `revdeck analyze` and `revdeck import`.
- Included `profile` and `diagnostics` in analyze/import JSON output.
- Documented profile behavior in README.
- Added index-level and CLI-level regression tests.

Verification:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

Non-obvious note:
- `ImportOutcome.run_id` continues to reference the Function Radar scoring run after successful import. Native importer diagnostics should be checked on the native analyzer run, not by loading `outcome.run_id`.
