# F-001 Graph Lab And Evidence Paths

Priority: P0

## Summary

Promote RevDeck's existing local relation rendering into a first-class Graph Lab workspace lens. Users should be able to open the current object as a graph root, inspect xrefs and relation direction, and follow evidence paths from functions to strings, imports, notes, and findings.

## Must Have

- Add Graph Lab to workspace navigation and shortcuts.
- Show root object, relation direction, edge kind, neighbor object, and confidence/source where available.
- Support one-hop and bounded two-hop traversal.
- Let `Enter` jump to selected related object.
- Preserve current three-pane focus model.

## Acceptance

- A dangerous import caller can be opened in Graph Lab and navigated to its import/string evidence.
- Broken or missing refs render as diagnostics rather than panics.
- Snapshot tests cover normal, empty, and small-terminal graph views.
