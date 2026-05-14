# UI Designer Analysis

## TUI Shell
The default screen SHOULD be the working product, not a landing page. It should use:
- Left: workspace/lens navigation.
- Center: active lens, usually Overview or Function Radar.
- Right: inspector for selected object.
- Bottom: command bar and compact status line.

## First View
The first useful view SHOULD show project identity, artifact metadata, index status, Function Radar highlights, and suggested next actions. The product should immediately communicate that RevDeck knows what objects exist and where attention should go.

## Interaction Patterns
- Arrow keys or Vim-style movement for lists.
- Enter to jump into selected object.
- Back/forward history for Universal Jump.
- `/` for search.
- `:` for command mode.
- `n` note, `t` tag, `r` rename, `f` finding, where keybindings can later be configured.

## Lens Layouts
Function Radar:
- Dense table with score, function, size, calls, strings, and reasons.
- Inspector shows tags, notes, xrefs, strings, calls, and findings.

Binary Map:
- Sections/imports/strings/function list with object inspector.
- Hex/disassembly area can be basic at first.

Findings:
- Finding list with severity/status.
- Evidence inspector that shows linked objects and missing evidence warnings.

## Visual Direction
Use restrained terminal styling: clear selection state, status colors for severity, and compact tables. Avoid decorative panels. The TUI must remain readable over SSH and low-contrast terminal themes.

## Risks
- Huge graph views can become unreadable in a terminal. Graph Lab should start with local neighborhoods and path lists.
- Too many shortcuts without command palette discoverability will slow adoption.
