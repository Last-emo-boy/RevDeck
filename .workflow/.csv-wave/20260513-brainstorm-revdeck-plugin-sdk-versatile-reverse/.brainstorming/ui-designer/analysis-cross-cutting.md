# UI Designer Cross-Cutting Decisions

## 1. Information Architecture

RevDeck should remain a cockpit, not a plugin gallery. The user's primary loop is still: identify what to inspect next, jump through evidence, annotate, promote findings, and export. Plugin features should appear only where they improve that loop.

Recommended top-level layout:

- Cockpit: project status, active artifact, active lens, focus, selected object, plugin run/status chips.
- Workspace: built-in lenses, specialized labs, plugin lenses, experimental lenses.
- Main View: the active lens using a small set of host templates.
- Inspector: selected object context plus plugin-owned cards.
- Command / Status: command input, status, context help, plugin actions, diagnostics.

The existing three-pane structure is the right default. Plugin work should make the panes data-driven, not replace them.

## 2. Lens Registry Model

The current hard-coded lens list should become a `LensRegistry` assembled from core lenses and validated plugin manifests. Each entry should include:

- stable `lens_id`, display label, 3-letter badge, category, provider, stability, and sort order;
- supported object kinds and default navigation target;
- host renderer template: table, timeline, tree, graph-local, diff, field-grid, object-list, report-list, or diagnostics;
- command examples and context help;
- availability state: ready, empty, blocked, failed, running, missing-plugin-data, experimental.

Plugin lenses should not directly own navigation history. They should emit host navigation intents: open object, open edge, open run, open artifact, show diagnostics, create note, propose finding, or run command.

## 3. Plugin UI Slots

Use explicit slots so plugin UI is powerful but bounded:

- `workspace.lens`: adds a navigable lens row.
- `main.template`: fills a host-controlled table/tree/timeline/graph template.
- `inspector.card`: adds a bounded card for selected objects.
- `command.action`: registers commands and examples.
- `cockpit.chip`: shows short run, warning, permission, or diagnostic state.
- `triage.reason`: contributes explainable scoring rows.
- `finding.suggestion`: contributes unconfirmed finding drafts.
- `help.section`: contributes contextual help under the provider name.

Slots should have hard constraints: label length, max card height, max rows before paging, no raw terminal drawing in stable plugins, no global color override, no hidden network action from UI commands.

## 4. Command Deck

Command Deck should become the main discovery surface. In normal mode, the bottom bar should continue to show concise examples. In help mode, it should add dynamic sections:

- Available now: context commands for the current selection.
- Added by plugins: grouped by provider and capability.
- Requires permission: commands visible but marked blocked until granted.
- Recent runs: last plugin commands, status, duration, diagnostics.
- Examples: plugin-declared examples using realistic object targets.

New commands should follow namespaces that users can guess:

- `:plugins`
- `:plugin info <id>`
- `:plugin run <id> current`
- `:lens <id>`
- `:commands <plugin-id>`
- `:diagnostics plugin <id>`
- `:permissions <plugin-id>`

This avoids overloading scarce single-key shortcuts. Built-in keys can remain stable; plugin shortcuts should be opt-in aliases.

## 5. Inspector Panels

Inspector is the strongest integration point because it sits on the selected object. The default order should be:

1. Identity and stable ref.
2. Core attributes.
3. Score reasons.
4. Evidence and backlinks.
5. Notes/tags/status/rename.
6. Plugin cards.
7. Diagnostics and warnings.

Plugin cards should be collapsed when they are noisy, and expanded when the plugin is the active lens provider. Each card needs provider, run ID, confidence, timestamp, and "jump" targets. A plugin card without jumpable evidence should be treated as low trust for triage and finding workflows.

## 6. Cockpit Aesthetics

The visual language should be utilitarian, dense, and calm. The "deck" metaphor works best as instrumentation: status chips, provider badges, run indicators, and navigation context. Avoid decorative panels or broad color themes. Color should mean state:

- Cyan: focus/current cockpit state.
- Green: completed or confirmed.
- Yellow: warning, partial data, permission needed.
- Red: failed, blocked, unsafe, invalid.
- Magenta: experimental or plugin-provided.
- Gray: unavailable, empty, disabled.

Provider badges should use short stable text rather than icons, because terminal rendering and accessibility vary.

## 7. Keyboard Model

Keep the current model:

- `Tab` and `Shift+Tab` cycle panes.
- `Left` and `Right` move columns.
- `Up` and `Down` or `j` and `k` move within the focused pane.
- `Enter` opens, jumps, or activates.
- `?` or `h` opens contextual help.
- `:` enters command mode.
- `[` and `]` move history.

Plugin-aware additions should be command-based first. A user can discover and run them with Command Deck. If a plugin proposes shortcuts, the host should show them as unbound suggestions until the analyst opts in.

## 8. Discoverability

Users need to know what a plugin added, where it appears, and why something is not visible. Required discovery states:

- Install success: summary of lenses, commands, score rules, importers, exporters, and permissions.
- Empty lens: what data is missing and which command/importer can populate it.
- Blocked lens: permission or compatibility reason.
- Plugin contribution: provider badge on rows, cards, commands, and score reasons.
- Help overlay: "Added by <plugin>" grouped sections.
- Diagnostics: quick path from error to run details.

The product should distinguish `no data`, `not installed`, `permission denied`, `run failed`, and `schema incompatible`. These states should not collapse into a generic empty table.

## 9. Responsive Terminal Breakpoints

Current implementation switches to stacked layout when the body is below 72 columns or 10 rows. Plugin UI should define richer breakpoints:

- Compact: under 80 columns or under 20 rows. Show one primary pane at a time, keep Cockpit to one line, bottom bar to status plus command prompt, and move help to paged overlay.
- Standard: 80 to 119 columns. Use stacked or two-column layout with Workspace collapsed to badges and Inspector as a short drawer.
- Wide: 120 to 159 columns. Use the current three-pane cockpit: 20 columns Workspace, flexible Main, 32 columns Inspector.
- Extra wide: 160+ columns. Allow Main View secondary split for diff, trace detail, or graph side list while keeping Inspector stable.

Manifest validation should preview all plugin labels, badges, table columns, and help snippets against compact and wide layouts.

## 10. Cross-Role Tensions

Architecture and data roles favor constrained schemas and host-managed data. UI should align with that by making early plugin lenses declarative and template-driven. Product may want impressive custom labs quickly, but custom terminal renderers will fragment navigation, keyboard behavior, and accessibility. The compromise is to ship specialized templates first, then graduate custom rendering only behind experimental flags and snapshot tests.

Another likely tension is plugin author control over shortcuts and colors. The UI answer should be host ownership. Plugins can suggest labels, examples, and aliases, but RevDeck owns global shortcuts, focus behavior, state colors, and safety prompts.

## 11. Acceptance Criteria

- Every plugin contribution is discoverable from Command Deck.
- Every plugin-visible result has provider and run provenance.
- Every plugin lens has useful empty, blocked, failed, and partial states.
- No stable plugin can claim a global one-letter shortcut by default.
- Plugin labels and help render cleanly at compact and wide breakpoints.
- Inspector plugin cards include jumpable evidence where possible.
- Score and finding contributions clearly separate automated suggestions from analyst-confirmed work.
