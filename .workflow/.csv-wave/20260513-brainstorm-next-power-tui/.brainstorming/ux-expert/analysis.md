# UX Expert Analysis

## User Journey

The next iteration should reduce "where do I go now?" moments. Every screen should answer:

- What is currently selected?
- Why is it important?
- What can I do next?
- What evidence led here?
- How do I turn this into a durable conclusion?

## UX Improvements

- Graph Lab should show one-hop and two-hop context for the current object, with edge labels and evidence direction.
- Triage Queue should make analysis progress explicit: new, investigating, reviewed, promoted, dismissed.
- Command Deck should preview whether a command mutates session memory, project DB, export queue, or only navigation state.
- Failed analysis should be explained in product terms. Example: unknown file magic should say the file may not be PE/ELF or may be packed/encrypted, and point to Binary Map diagnostics or adapter imports.
- Finding promotion should be one command/action from a high-risk function or triage item, carrying evidence refs automatically.
- Recent objects and navigation breadcrumbs should make it easy to return after following xrefs.

## Acceptance Signals

- A new user can open a sample and discover Graph Lab without reading README.
- A user can find a dangerous import caller, view its evidence path, mark it reviewed, and promote it to a finding without memorizing command syntax.
- A failed parse gives a clear next step instead of only a structured error.
