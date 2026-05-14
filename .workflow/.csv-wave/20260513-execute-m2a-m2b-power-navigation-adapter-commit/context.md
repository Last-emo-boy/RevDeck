# Execution Report -- M2A TUI Power Navigation And M2B Adapter Commit Pipeline

Status: completed

## Objective

Advance M2A and M2B from the brainstorm into concrete, verified implementation slices.

## Delivered

### M2A TUI Power Navigation

- Graph Lab is now a first-class workspace lens through `NavigationLens::LocalGraph` in `WORKSPACE_LENSES`.
- `G` opens Graph Lab around the current selected object.
- `p` / Ctrl+P opens a minimal Command Deck overlay.
- Command Deck previews common commands, current object context, and relation availability.
- Command/status area now includes a breadcrumb-style trail line.

### M2B Adapter Commit Pipeline

- Added schema version 6 with:
  - `plugin_attributes`
  - `plugin_diagnostics`
- Added host-mediated ObjectBatch commit:
  - validates manifest and ObjectBatch
  - checks project_write permissions
  - commits objects, edges, attributes, and diagnostics through the host
  - records plugin run audit status and commit summary
- Added CLI commands:
  - `revdeck plugin commit <project_dir> <plugin_dir>`
  - `revdeck plugin run <project_dir> <plugin_dir> --commit`
- `plugin run` is currently deterministic fixture replay, not arbitrary external process execution.

## Verification

Passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p revdeck-tui`
- `cargo test -p revdeck-tui-tests`
- `cargo test -p revdeck-db`
- `cargo test -p revdeck-plugin-host`
- `cargo test -p revdeck-plugin-sdk-tests`
- `cargo test --workspace`
- `cargo run -p revdeck-cli -- plugin commit <temp-project> fixtures/plugins/valid-minimal`
- `cargo run -p revdeck-cli -- plugin run <temp-project> fixtures/plugins/valid-minimal --commit`
- `cargo install --path crates/revdeck-cli --locked`
- `revdeck plugin commit <temp-project> fixtures/plugins/valid-minimal`
- `revdeck plugin run <temp-project> fixtures/plugins/valid-minimal --commit`

## Limits

- M2B does not execute arbitrary external plugin processes yet.
- Plugin-contributed `artifact_key` values are only retained when the project already has a matching artifact row; this avoids creating incomplete artifact records from ObjectBatch facts.
- Full Trace/Diff/Crash/Firmware Labs and custom plugin renderers remain future work.
