# 0014: Use HTTPS polling before a message broker

## Status
Accepted

## Context
V0.1 needs reliable outbound delivery without operating another distributed system.

## Decision
Implement database-backed HTTPS polling behind a transport boundary before adopting NATS JetStream.

## Consequences
Initial deployment remains approachable. Polling needs leases, idempotency and backoff; NATS can replace transport without changing domain policy.
