# F-003 Command Deck And Fuzzy Object Search

Priority: P0

## Summary

Add an overlay command palette for commands, objects, recent targets, help, and mutation previews. This turns the command language into a discoverable interface without removing typed commands.

## Must Have

- Open with `Ctrl+P` or `p`.
- Tabs or modes for Commands, Objects, Recent, and Help.
- Fuzzy match object names, refs, imports, strings, and commands.
- Show whether an action mutates navigation, session memory, database, export queue, or plugin state.
- Execute the selected action with `Enter`.

## Acceptance

- A user can search `system`, jump to an import, inspect xrefs, and create a note without memorizing exact command syntax.
- Reducer tests cover overlay navigation and command execution previews.
