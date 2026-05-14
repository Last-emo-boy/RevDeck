# F-002 Terminal Workspace Shell

## Intent
Deliver the core TUI product surface for RevDeck. The UI MUST support dense keyboard-first analysis and should open directly into useful project context.

## Scope
- Left workspace navigation.
- Center active lens.
- Right object inspector.
- Bottom command bar and status line.
- Basic lens switching and selection state.

## Acceptance Signals
- User can move through workspace sections without mouse input.
- Selection updates the inspector.
- Command bar can accept core commands.
- Layout remains usable on typical terminal sizes.

## Dependencies
F-001 for real project data; can be prototyped with fixtures.
