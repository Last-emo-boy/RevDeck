# E2 Implementation Exploration

## Basis
- Source: `RevDeck.txt`
- Context: `.workflow/scratch/20260513-revdeck-v01-binary-triage/context.md`
- Brainstorm specs: `F-001 Project Ingest And Index`, `F-002 Terminal Workspace Shell`, `F-003 Function Radar`
- Boundary: v0.1 Binary Triage only. Do not plan Trace/Diff/Firmware/Crash/Protocol/Memory labs as shipped features.

## Fresh Rust Scaffold

Use a single Rust workspace so the first version stays easy to build and test:

```text
Cargo.toml
crates/
  revdeck-cli/       # binary entrypoint and CLI argument parsing
  revdeck-core/      # project model, object IDs, scoring, commands
  revdeck-db/        # SQLite schema, migrations, repositories
  revdeck-index/     # binary parsing and index pipeline
  revdeck-tui/       # Ratatui app, views, input loop
fixtures/
  binaries/
tests/
```

Recommended crates:
- `clap` for commands.
- `ratatui` + `crossterm` for TUI.
- `rusqlite` or `sqlx` for SQLite. Prefer `rusqlite` for simple embedded sync access in v0.1 unless async jobs become necessary.
- `goblin` or `object` for ELF metadata. Prefer `object` for broad binary format metadata; add `goblin` if ELF-specific parsing ergonomics matter.
- `sha2`, `memmap2`, `regex`, `aho-corasick`, `serde`, `serde_json`, `thiserror`, `anyhow`, `uuid` or deterministic typed IDs.

Keep plugin API out of the initial scaffold. Use internal traits such as `BinaryParser`, `IndexerStep`, and `ReportExporter` so F-008 has a boundary without a marketplace.

## CLI Commands

The CLI should prove the product loop without forcing users into the TUI for automation:

```text
revdeck init <project-dir>
revdeck open <project-dir>                         # enters TUI
revdeck import <project-dir> <binary-path>          # registers artifact and indexes by default
revdeck index <project-dir> [artifact-id]
revdeck stats <project-dir>
revdeck report <project-dir> --format md|json --out <path>
revdeck tui <project-dir>
```

`revdeck open ./target.elf` is a useful product shorthand, but implementation should normalize it into an implicit project directory such as `target.elf.revdeck/` or `.revdeck/` only after the project storage decision is explicit. Feature planning should decide this early because it affects UX, tests, and artifact copying.

## SQLite Storage Pattern

Use append-friendly, deterministic project data. Suggested v0.1 tables:

```text
project_meta(key, value)
artifacts(id, source_path, stored_path, sha256, size, kind, created_at)
analysis_runs(id, artifact_id, status, tool_version, started_at, finished_at, error_json)
sections(id, artifact_id, name, addr, offset, size, flags, entropy)
symbols(id, artifact_id, name, addr, size, kind, binding)
imports(id, artifact_id, module, name, ordinal, addr)
strings(id, artifact_id, value, addr, offset, length, encoding)
functions(id, artifact_id, name, addr, size, source, call_count, string_count, score)
xrefs(id, artifact_id, src_kind, src_id, dst_kind, dst_id, relation, addr)
score_reasons(id, function_id, code, weight, detail)
object_notes(id, object_kind, object_id, body, created_at, updated_at)
tags(id, name)
object_tags(object_kind, object_id, tag_id)
renames(id, object_kind, object_id, old_name, new_name, created_at)
findings(id, title, severity, status, summary, created_at, updated_at)
finding_evidence(finding_id, object_kind, object_id, note)
```

Access pattern:
- Repositories expose typed methods: `ProjectRepo`, `ArtifactRepo`, `IndexRepo`, `RadarRepo`, `MemoryRepo`, `FindingRepo`.
- Writes run inside one transaction per import/index run. Store structured failures in `analysis_runs.error_json`.
- Stable object IDs should be derived from artifact hash + kind + address/offset/name where possible, not random IDs. This keeps reopen/re-index behavior deterministic.
- Store raw object facts separately from analyst edits. Re-indexing can replace `sections`, `strings`, `imports`, `functions`, `xrefs`, and `score_reasons` for a run without destroying notes/tags/findings.

## Binary Parsing And Indexing Flow

v0.1 should be honest about what can be recovered without a full disassembler:

1. Register artifact: canonicalize path, compute `sha256`, record source path, optionally copy into `.revdeck/artifacts/`.
2. Detect format and architecture with `object`/`goblin`.
3. Index sections, symbols, imports, entrypoint, and basic metadata.
4. Extract printable strings from mapped bytes with offset, approximate virtual address when section mapping is available, encoding, and length.
5. Create functions from symbols first. For stripped binaries, create a limited fallback set from entrypoint/exported symbols/import call targets only if available; mark `source=fallback`.
6. Build xrefs available from simple evidence:
   - function to string when a string address is referenced in function byte ranges if relocations/symbol ranges make this feasible;
   - function to import when relocation/import call evidence is available;
   - symbol/function containment relations.
7. Score functions using deterministic reasons:
   - dangerous import references: `system`, `popen`, `exec*`, `strcpy`, `sprintf`, `gets`, etc.;
   - sensitive strings: `password`, `token`, `/bin/sh`, `cmd`, `admin`, URL/path/auth terms;
   - size/call/string counts;
   - entrypoint proximity when known;
   - user tags as a separate analyst signal.
8. Persist counts and status for Overview and Function Radar.

Avoid promising complete CFG, decompilation, or accurate function recovery in v0.1. The implementation plan should define "confidence/source" fields so the UI can show whether a function came from symbols, parser metadata, or heuristic fallback.

## Ratatui App Structure

Use a predictable Elm-style loop:

```text
AppState
  project
  route/lens: Overview | BinaryMap | Functions | Strings | Imports | Notes | Findings
  selection: ObjectRef
  command_bar
  status
  data caches for visible lens

Event -> Action -> Update AppState -> Render
```

Suggested modules:

```text
revdeck-tui/src/
  app.rs
  event.rs
  action.rs
  layout.rs
  command_bar.rs
  views/
    overview.rs
    functions.rs
    strings.rs
    imports.rs
    inspector.rs
    notes.rs
    findings.rs
```

Layout:
- Left navigation: Overview, Binary Map, Function Radar, Strings, Imports, Notes, Findings.
- Center lens: dense table/list/detail for selected section.
- Right inspector: selected object metadata, xrefs, tags, notes, finding links.
- Bottom command bar: normal/status mode and `:` command input.

State should not directly query SQLite from render functions. Load visible data through commands/actions and cache view models. This makes render tests and command tests deterministic.

## Command Bar

Implement a small explicit parser before any query language:

```text
:find string <term>
:find function <term>
:xrefs <object>
:tag <object|selected> <tag>
:note <object|selected>
:rename <function|selected> <name>
:finding new <severity> <title>
:report md|json <path>
:open <object>
```

Parsing pattern:
- `CommandParser::parse(&str) -> Result<Command, CommandError>`
- `CommandExecutor::execute(Command, &mut AppState, &Repos) -> Result<ActionOutcome>`
- Keep fuzzy search and SQL-like filters out of v0.1 unless later planning has spare capacity.

UX rules:
- Empty `:` enters command mode.
- `Esc` exits command mode.
- `Enter` executes.
- Failed commands stay in command mode and show a concise error in status.
- Commands operate on `selected` by default to keep keyboard flow fast.

## UX Findings

Implementation should optimize for "where should I look first":
- Initial TUI route should be Overview if no artifact is indexed, otherwise Function Radar or Overview with top-ranked functions visible.
- Function Radar table columns: score, name/address, size, calls, strings, reasons.
- Inspector should show scoring reasons, related strings/imports/xrefs, tags, notes, and finding evidence links.
- Universal object navigation in v0.1 can be local and table-based: selecting a string can show referencing functions; selecting an import can show candidate caller functions; selecting a function can jump to strings/imports/xrefs.
- Do not build a global graph renderer in v0.1. A compact xref list gives most of the planned value with less risk.

## Testing Pattern

Prioritize deterministic fixtures:
- Tiny ELF fixture with known sections, imports, symbols, and strings.
- Stripped/minimal binary fixture to verify graceful degradation.
- Corrupt/non-binary fixture to verify structured import errors.
- Seeded SQLite project fixture for TUI and command tests.

Test layers:
- Unit tests for command parser, scoring rules, object ID generation, string extraction, report serialization.
- DB migration/repository tests using temporary project directories.
- Index integration tests: fixture binary -> exact object counts and selected values.
- TUI render snapshot tests with `ratatui::backend::TestBackend` for Overview, Function Radar, Inspector, and command errors.
- CLI smoke tests with `assert_cmd`: init/import/stats/report/open failure paths.

Acceptance criteria should be count-based and reason-based, not visual-only:
- Fixture import creates artifact, analysis run, sections, strings, imports, functions, and score reasons.
- Reopen project preserves notes/tags/renames/findings.
- Re-index does not erase analyst memory.
- Function Radar sorting is stable across runs.

## Feature-Level Planning Implications

Suggested implementation sequence:
1. Workspace scaffold, error type, typed object refs, and CLI skeleton.
2. SQLite project creation, migrations, repositories, and artifact registration.
3. Binary metadata/string/import/symbol indexing with deterministic fixtures.
4. Function model and scoring service with explainable score reasons.
5. Ratatui shell with Overview, Function Radar, Inspector, and command bar.
6. Notes/tags/renames/finding persistence and command actions.
7. Markdown/JSON report export.
8. Cross-feature integration tests and fixture documentation.

Major risk:
- Accurate function and xref recovery is the hardest part if the binary is stripped. v0.1 should define degraded behavior clearly instead of depending on full disassembly. If full call/xref quality becomes mandatory, plan a separate adapter to consume radare2/Ghidra JSON rather than implementing a disassembler pipeline first.
