# 0007: Make Authorized Scope mandatory

## Status
Accepted

## Context
Active diagnostics and security assessment must have explicit, reviewable authorization.

## Decision
Resolve every active target from a valid organization-owned Authorized Scope. Public targets require additional permission.

## Consequences
Arbitrary browser targets are impossible by design. Scope verification and lifecycle become central operational workflows.
