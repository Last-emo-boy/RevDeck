# UI Designer Analysis

## TUI Direction

The three-pane shell should remain. The next iteration should make the interface feel more "operational cockpit" than static tables:

- Left: workspace lens and queue status.
- Center: focused dense work surface.
- Right: inspector, evidence path, and action preview.
- Bottom: command deck, status, job state, and key hints.

## High-Value UI Changes

- Add Graph Lab to the workspace nav with badge `GPH` or `REL`.
- Add a breadcrumb line: lens / selected object / relation depth / current filter.
- Replace static command help with context-aware action chips: open, xrefs, note, tag, promote, export.
- Show status chips for analysis state, plugin runs, queued exports, unsaved session memory, and parse warnings.
- Add no-data and failed-parse panels with concrete next commands instead of empty tables.
- Add visual ranking in Function Radar using compact score bars and severity color accents.
- Add Command Deck overlay with tabs: Commands, Objects, Recent, Help.

## Interaction Changes

- `p` or `Ctrl+P`: open Command Deck.
- `/`: search within current lens.
- `G`: open Graph Lab for current object.
- `Space`: mark queue item reviewed or toggle selection.
- `a`: open action menu for current object.
- `Enter`: primary action remains open/jump.

## Visual Constraints

- Keep cards shallow and dense; avoid nested cards.
- Use stable widths and row heights so selection movement never shifts layout.
- Make small-terminal fallback intentional: stack panes, keep command deck usable, and show truncated but meaningful labels.
