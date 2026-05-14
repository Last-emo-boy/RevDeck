# F-007 Graph Lab Seed

## Intent
Introduce graph reasoning without overbuilding visualization. RevDeck SHOULD support local xref/call/path navigation that works well in a terminal.

## Scope
- Local xref graph.
- Callers/callees neighborhood.
- Simple source-to-sink path listing.
- Optional compact ASCII tree/path view.

## Acceptance Signals
- User can inspect a local neighborhood around a function/import/string.
- Path output remains readable in terminal.
- Graph data reuses the unified object graph.

## Dependencies
F-001, F-004.
