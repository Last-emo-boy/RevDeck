# F-002 Adapter Runner And ObjectBatch Commit

Priority: P0

## Summary

Turn the M1 plugin dry-run preview into a useful local adapter pipeline. The host runs a plugin process, validates ObjectBatch output, commits facts transactionally, and records exactly what plugin contributed.

## Must Have

- Add `revdeck plugin run` for audited local adapter execution.
- Add `revdeck plugin commit` or `--commit` gated by validation and permissions.
- Validate and commit objects, edges, attributes, diagnostics, and provenance.
- Record plugin run status, manifest digest, input digest, output digest, diagnostics, and contribution counts.
- Roll back the whole commit on invalid batch or permission denial.

## Acceptance

- A fixture plugin can add objects/edges to a project and re-run idempotently.
- Denied permissions produce structured sanitized diagnostics.
- Plugin contributions remain queryable by plugin run.
