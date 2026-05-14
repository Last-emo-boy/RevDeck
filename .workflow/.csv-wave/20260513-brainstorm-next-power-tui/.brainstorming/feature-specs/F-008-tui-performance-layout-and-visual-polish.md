# F-008 TUI Performance Layout And Visual Polish

Priority: P0

## Summary

Make the TUI feel faster, clearer, and more stable as projects grow. This is a quality multiplier for every other feature.

## Must Have

- Status chips for analysis, plugin runs, queued exports, unsaved memory, and parse warnings.
- Breadcrumbs showing lens, selected object, filter, and navigation history.
- No-data panels with next actions.
- Large-list paging or bounded query models.
- Stable render dimensions across row movement, help overlays, and small terminals.

## Acceptance

- Large fixture projects do not cause unbounded object loads in the TUI.
- Snapshot tests cover normal and small-terminal layouts.
