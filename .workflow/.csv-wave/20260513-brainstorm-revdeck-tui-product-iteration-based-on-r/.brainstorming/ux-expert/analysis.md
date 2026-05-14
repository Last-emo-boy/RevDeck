# UX Expert Analysis

## Core UX Loop
RevDeck should guide this loop:
Import target -> index -> inspect prioritized objects -> jump through context -> annotate -> create finding -> export.

Every major workflow should preserve analyst intent. A user should be able to return days later and understand what was reviewed, what remains suspicious, and what evidence supports each conclusion.

## Information Architecture
The user's mental model should be:
- Artifacts are inputs.
- Objects are things discovered from artifacts.
- Edges explain relationships.
- Lenses are different ways of looking at the same objects.
- Notes/tags/findings are durable analyst knowledge.

## Cognitive Load Controls
- Function Radar answers where to start.
- Inspector answers why the current object matters.
- Backlinks answer how the user got here.
- Status/tag filters answer what remains.
- Findings answer what can be delivered.

## Command Design
Commands should map to analyst questions:
- `:find string password`
- `:xrefs system`
- `:tag current suspicious`
- `:rename current handle_debug_command`
- `:finding new high "Unauthenticated command execution"`
- `:functions where calls(system) and references("/bin/sh")`

## User Value Risks
- If notes are disconnected from object navigation, RevDeck becomes another browser.
- If Function Radar cannot explain scores, users will not trust it.
- If report export drops evidence context, findings will not be credible.
