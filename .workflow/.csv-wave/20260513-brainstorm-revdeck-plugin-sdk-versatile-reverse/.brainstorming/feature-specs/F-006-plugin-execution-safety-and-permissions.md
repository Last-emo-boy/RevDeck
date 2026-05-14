# F-006 Plugin Execution Safety And Permissions

## Purpose

Protect sensitive samples, private notes, credentials, memory dumps, traces, and unpublished findings while still allowing useful local plugins.

## User Value

Analysts can run plugins with clear expectations: what is read, what is written, what is blocked, and what evidence was produced.

## Requirements

- Plugins MUST default to least privilege.
- Network, process spawn, secrets, environment access, broad filesystem access, and direct database access MUST be denied unless explicitly granted.
- Plugin runs MUST be audited with manifest digest, input digest, config digest, permissions, diagnostics, timing, accepted output counts, and commit result.
- Plugin failures MUST be sanitized and non-mutating unless a checkpointed import mode is explicitly supported.
- Redaction defaults SHOULD protect credential candidates, private keys, packet payloads, memory strings, and raw sample paths in reports.

## Runtime Model

State machine:

`discovered -> validated -> installed -> configured -> queued -> starting -> running -> committing -> succeeded | failed | canceled -> superseded`

Permission scopes:

- `artifact_read`
- `project_read`
- `project_write`
- `filesystem_read`
- `filesystem_write`
- `network`
- `process_spawn`
- `secrets`
- `environment`
- `resource_limits`

## TUI/CLI Affordances

- Command Deck shows grant summary before execution.
- Cockpit shows blocked/running/failed plugin chips.
- Empty lens states explain missing permissions versus no data.
- `revdeck plugin run --dry-run` validates permissions and inputs without execution.

## Test Strategy

- Fake plugins attempting denied network, filesystem, process, env, DB, timeout, output flood, malformed protocol, and crash behavior.
- Assert diagnostics are sanitized and no project mutation occurs.
- Cross-platform process behavior tests where feasible.

## Rollout Notes

Implement with the first plugin runner. Public distribution should wait until this is understandable and testable.
