# 0019: Idempotent agent results

Status: Accepted

## Context

Outbound agents retry after network ambiguity. Re-importing a result could
duplicate observations and evidence.

## Decision

Reserve one durable result receipt per job using result identity/version and a
payload SHA-256. Identical retries succeed as no-ops; conflicting results fail.

## Consequences

Retries are safe and auditable. Corrections require a new job rather than
mutating completed evidence.
