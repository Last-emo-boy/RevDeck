# F-004 Universal Object Navigation

## Intent
Make every indexed and analyst-created object navigable. RevDeck MUST support object jumps across reverse engineering evidence.

## Scope
- Typed edges between functions, strings, imports, xrefs, notes, tags, and findings.
- Jump actions from selected object to related objects.
- Back/forward navigation history.
- Inspector backlinks.

## Acceptance Signals
- String -> xref -> function -> import navigation works.
- Finding -> evidence -> object navigation works.
- Back/forward history restores prior selections.
- Broken links are surfaced clearly.

## Dependencies
F-001, F-002.
