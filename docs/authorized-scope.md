# Authorized Scope

Authorized Scope is the source of every active target. It is organization-owned and records type, normalized value, internal/public environment, status, verification method, verifier, validity window and notes.

## Lifecycle

`PENDING` → `VERIFIED` or `APPROVED` → `REVOKED`/`EXPIRED`. Hostnames may prove control using a DNS TXT or bounded HTTP file challenge. IP and CIDR require explicit administrative approval. Approval and revocation create audit events.

## Resolution

The browser provides `scopeId`, never an arbitrary public target. The server loads it by organization, verifies time and state, then normalizes it. URL fragments are removed; IP/CIDR values use canonical parsing; hostnames are lowercased. DNS rebinding defenses and resolution pinning belong in the job handoff implementation.

Public scopes require the distinct `public_scan.run` permission plus module, agent, rate and concurrency policy. Ordinary roles do not receive it.
