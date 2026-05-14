# M1 SDK Contract Preview Execution

Source plan: `.workflow/scratch/20260513-plan-m1-sdk-contract-preview/plan.json`

Status: completed

## Delivered

- Added `revdeck-plugin-sdk` with manifest, permissions, ObjectBatch, and validation contracts.
- Added `revdeck-plugin-host` with manifest validate/inspect, plugin directory test, ObjectBatch dry-run, digest helpers, and M1 safety skeleton.
- Added plugin run audit persistence in `revdeck-db` schema version 5.
- Added CLI commands:
  - `revdeck plugin validate <revdeck-plugin.toml>`
  - `revdeck plugin inspect <revdeck-plugin.toml>`
  - `revdeck plugin test <plugin_dir>`
- Added fixtures under `fixtures/plugins/` and integration coverage under `tests/plugin-sdk/`.
- Updated `README.md` with `Plugin SDK Preview` usage, manifest example, safety caveats, and roadmap context.

## Verification

Passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo run -p revdeck-cli -- plugin validate fixtures/plugins/valid-minimal/revdeck-plugin.toml`
- `cargo run -p revdeck-cli -- plugin inspect fixtures/plugins/valid-minimal/revdeck-plugin.toml`
- `cargo run -p revdeck-cli -- plugin test fixtures/plugins/valid-minimal`
- `cargo install --path crates/revdeck-cli --locked`
- `revdeck plugin validate fixtures/plugins/valid-minimal/revdeck-plugin.toml`
- `revdeck plugin inspect fixtures/plugins/valid-minimal/revdeck-plugin.toml`
- `revdeck plugin test fixtures/plugins/valid-minimal`

## Notes

- Initial `cargo install` compiled successfully but could not replace `C:\Users\ES&E\.cargo\bin\revdeck.exe` because a stale `revdeck analyze C:\Windows\System32\notepad.exe` process held the executable open. After stopping that process, the install and installed CLI smoke checks passed.
- M1 intentionally remains a local SDK preview. It does not provide public marketplace behavior, custom TUI plugin renderers, direct SQLite access for plugins, or a hardened OS sandbox.
