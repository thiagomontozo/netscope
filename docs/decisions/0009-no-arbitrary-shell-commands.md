# 0009: Reject arbitrary shell commands

## Status
Accepted

## Context
Free-form commands or arguments would turn a diagnostics product into a remote execution surface.

## Decision
Accept only registered module IDs and schema-validated parameters. Agents build bounded tool invocations internally.

## Consequences
Capabilities are safer and reviewable. Each useful option requires an explicit profile or schema change.
