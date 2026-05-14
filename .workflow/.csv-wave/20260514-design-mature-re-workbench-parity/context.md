# Mature Native RE Workbench Parity Design

## Summary

RevDeck should move toward a mature reverse engineering workbench without becoming a frontend for another tool. The product direction is native-first: RevDeck owns the binary parser, analyzer passes, object graph, project state, TUI interaction model, command language, and plugin boundary.

The competitive bar is not "copy commands". The bar is workflow parity:

- Open large binaries quickly and keep the interface responsive.
- Expose analysis as explicit stages instead of one opaque blocking step.
- Let users navigate by address, object, function, xref, search hit, and history.
- Make every TUI view actionable: inspect, seek, annotate, rename, tag, link evidence, export.
- Persist project knowledge as first-class state: flags, names, notes, findings, layouts, analysis cache.
- Allow advanced users to compose commands, aliases, profiles, and plugins.

## Current RevDeck Position

Already present:

- One-shot `analyze` command that creates a workspace and opens the TUI.
- SQLite project database for artifacts, runs, objects, edges, findings, annotations, native blocks, instructions, and CFG edges.
- PE and ELF import path through the native analyzer.
- Function Radar, Triage Board, Graph Lab, object navigation, notes, tags, findings, and report export.
- Three-pane TUI with pane focus, navigation history, help overlay, and command deck.
- Plugin SDK preview with manifest validation and ObjectBatch host commit.

Main gaps:

- `analyze` still blocks until full import and native CFG collection finish.
- `import_binary` reads the whole file into memory and runs all native passes in one synchronous path.
- Analysis is not yet modeled as resumable jobs with progress, budgets, cancellation, or per-pass status.
- TUI has object lists and local graph, but no true address seek, hex/disassembly split, saved layouts, or tabbed workspaces.
- Command language is useful but not yet composable: no aliases, macros, pipeline output, repeat count, address expressions, or command history persistence.
- Manual correction loop is shallow: users can rename/tag/note, but cannot yet define functions, resize functions, create xrefs, mark data/code, or rerun affected passes.

## Product Pillars

### 1. Staged Native Analysis

Analysis should become a pass pipeline:

1. `parse`: identify format, architecture, entrypoint, sections, imports, symbols.
2. `surface`: strings, entropy, suspicious imports, section anomalies, packer hints.
3. `seed`: entrypoint, symbols, import thunks, direct call targets.
4. `linear`: decode executable ranges with budget limits.
5. `cfg`: basic blocks, branch edges, calls, local xrefs.
6. `dataflow`: register sources, stack slots, constants, argument hints.
7. `triage`: score functions, generate next actions, refresh findings gaps.
8. `enrich`: optional deep passes, plugin passes, expensive graph expansion.

Profiles:

- `quick`: parse + surface + seed + bounded linear scan. Target: open TUI quickly on large binaries.
- `balanced`: current default quality level, with native CFG for bounded function set.
- `deep`: full native CFG and heavier dataflow where supported.
- `custom`: explicit pass list and budgets.

Important design rule: every pass writes a durable status record before and after execution. The UI must be able to show partial data immediately.

### 2. Job Model And Large Binary UX

Large binaries should never feel frozen. RevDeck should treat analysis as a visible job queue:

- `analysis_jobs`: one row per pass or pass group.
- Status: `queued`, `running`, `succeeded`, `failed`, `canceled`, `skipped`.
- Progress fields: current unit, total units, objects produced, diagnostics count.
- Budget fields: byte limit, function limit, time limit, pass profile.
- Control: cancel, rerun, retry failed, run deeper from current object.

CLI behavior:

- `revdeck analyze target.exe` should default to a responsive profile.
- `revdeck analyze target.exe --profile quick` should open as soon as parse/surface data exists.
- `revdeck analyze target.exe --profile deep --no-tui` should be acceptable for batch mode.
- `revdeck jobs <project>` should list running and historical jobs.
- `revdeck analyze <binary> --defer-deep` should create the project and queue deeper work.

TUI behavior:

- Cockpit shows pass status and progress.
- Overview shows what is available now and what is pending.
- Command Deck includes `:analyze deeper`, `:jobs`, `:cancel job`, `:rerun failed`.
- Views tolerate partial data: Functions can say "seeded only", Graph Lab can say "CFG pending".

### 3. Command Language

RevDeck should keep its own command language, designed around object graph operations:

- Navigation: `seek`, `open`, `back`, `forward`, `history`.
- Search: `find string`, `find import`, `find bytes`, `find asm`, `find object`.
- Xrefs: `xrefs current`, `refs current`, `calls current`, `callers current`.
- Analysis: `analyze quick`, `analyze function current`, `analyze range 401000 402000`.
- Manual model edits: `function add`, `function resize`, `xref add`, `data mark`, `code mark`.
- Memory: `tag`, `note`, `rename`, `status`, `flag`.
- Findings: `finding new`, `finding link`, `finding promote`.
- UI: `view`, `tab new`, `layout save`, `layout load`.

Composability can come later, but the grammar should reserve space for:

- Address expressions: `entry`, `current`, `function.start`, `0x401000+0x20`.
- Repeat counts: `10 down`, `5 seek next`.
- Aliases: `alias danger = find import CreateProcess`.
- Macros: named command sequences saved in the project.
- Structured output for CLI mode: `--json` per command.

### 4. TUI Workbench Model

RevDeck should evolve from fixed three-pane shell to a tabbed workbench:

- `Tab` moves focus between panels.
- `t` opens tab control.
- `T` creates a new tab layout.
- `"` or command palette changes the active panel view.
- `|` and `-` can eventually split panels, but this should wait until the render/state model is ready.
- Layouts are saved per project.

Baseline tabs:

- `Triage`: Workspace + Function Radar + Inspector.
- `Disasm`: Function list + disassembly + Inspector.
- `Map`: Sections/entropy + hex preview + strings/imports side panel.
- `Graph`: Local graph + callers/callees + evidence.
- `Findings`: Findings + evidence + report preview.

First TUI additions:

- Add a Jobs/Analysis panel before deep layout work.
- Add an Address/Seek status row in Cockpit.
- Add Disassembly view backed by existing `instructions` table.
- Add Hex view backed by file offset ranges and section mappings.

### 5. Project Knowledge Model

Project state should become as important as analyzer output:

- Names: user renames override analyzer names but preserve original source.
- Flags: named locations and object bookmarks.
- Comments: address-level and object-level notes.
- Function edits: manual function boundaries, blocks, confidence, source.
- Data/code marks: user-labeled regions.
- Findings: evidence graph and report state.
- Layouts: saved TUI tabs and panels.
- Analysis cache: pass inputs, versions, budgets, and invalidation.

This makes RevDeck better for long-running analysis than a transient command shell.

### 6. Plugin SDK Direction

Plugins should extend RevDeck without escaping the native-first model.

Plugin kinds:

- `analysis-pass`: produces ObjectBatch, diagnostics, attributes, scores.
- `view-provider`: declares read-only view model data, not arbitrary terminal drawing in the first version.
- `rule-pack`: contributes scoring rules and triage next actions.
- `importer`: adds supported artifact formats through controlled object batches.
- `exporter`: writes reports or evidence packages.

SDK contracts:

- Stable object schema and permission model.
- Versioned manifest compatibility.
- Deterministic dry-run fixture tests.
- Host-owned commit transaction.
- Per-plugin diagnostics and provenance.
- No direct SQLite access.

## Non-Goals

- Do not depend on external reverse engineering tools at runtime.
- Do not build a compatibility layer for another tool's command set.
- Do not import another tool's project format as the primary workflow.
- Do not make deep auto-analysis block initial project opening.
- Do not prioritize visual flash over analyzer correctness and responsiveness.

## Implementation Roadmap

### P0: Responsive Analyze

Goal: make large binaries usable.

- Add `AnalysisProfile` to `revdeck-index`.
- Add `--profile quick|balanced|deep` to `analyze` and `import`.
- Change quick profile to skip or bound expensive native CFG collection.
- Store selected profile in run diagnostics or metadata.
- Update README with large binary workflow.

First acceptance:

- `revdeck analyze large.exe --profile quick` returns quickly relative to default deep analysis.
- TUI opens with sections/imports/strings/functions that are already known.
- Summary JSON includes profile and skipped pass diagnostics.

### P1: Pass Status And Jobs

Goal: make analysis visible and controllable.

- Add `analysis_jobs` migration.
- Insert job rows for parse/surface/seed/linear/cfg/dataflow/triage.
- Add `revdeck jobs <project>`.
- Add TUI Jobs lens and Cockpit status.
- Add cancel/rerun command stubs.

### P2: Seek, Disassembly, Hex

Goal: make RevDeck feel like a real binary workbench.

- Add command parser support for `seek`, `pd`, `px`, `s`.
- Add address resolver for entrypoint, current object, function boundaries, and raw hex.
- Add Disassembly lens backed by `instructions`.
- Add Hex lens with section/file offset mapping.
- Add navigation history entries for address seeks.

### P3: Manual Correction Loop

Goal: let users fix analyzer output.

- Add flags and address comments.
- Add user function records or function override metadata.
- Add commands for function add/resize/delete.
- Add user xref add/remove.
- Track analyzer facts vs user facts separately.

### P4: Analysis Pass Registry

Goal: make native analysis extensible and rerunnable.

- Define pass trait/config internally.
- Register built-in passes with inputs/outputs/budgets.
- Support rerun pass on artifact/function/range.
- Add invalidation rules when user edits boundaries.

### P5: Advanced Workbench

Goal: specialized labs without losing core simplicity.

- Dataflow graph view.
- Path queries between source and sink evidence.
- Diff Lab for function/string/import changes.
- Trace Lab for JSONL execution traces.
- Firmware Lab for directory and multi-artifact cases.
- Rule-pack driven triage and finding templates.

## Recommended Next Slice

Implement P0 as the next code iteration:

1. Add `AnalysisProfile` enum in `revdeck-index`.
2. Extend `ImportOptions` with `profile`.
3. Add CLI flags:
   - `revdeck analyze <binary> --profile quick|balanced|deep`
   - `revdeck import <project> <binary> --profile quick|balanced|deep`
4. In `quick`, skip full native CFG/dataflow and emit a recoverable diagnostic such as `pass_skipped_by_profile`.
5. Keep current behavior as `balanced` initially to avoid changing default output too aggressively.
6. Add tests proving quick profile still indexes parse/surface/seed facts and records the skipped-pass diagnostic.

This slice directly addresses the user's large EXE concern while laying the schema/API foundation for later job orchestration.

