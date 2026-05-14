# F-008 External Tool Adapter Boundary

## Intent
Keep RevDeck extensible without delaying MVP. Adapter contracts SHOULD normalize external tool outputs into RevDeck objects and edges.

## Scope
- Importer/analyzer interface definitions.
- Adapter manifest shape.
- Fixture JSON contract for at least one external-style import.
- Error reporting and version metadata.

## Acceptance Signals
- Mock adapter output can create objects and edges.
- Adapter failures do not corrupt project DB.
- Analysis run records include adapter identity and version.

## Dependencies
F-001.
