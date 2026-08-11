# 0001: Use Go for the control plane

## Status
Accepted

## Context
The control plane needs bounded concurrency, portable deployment, explicit error handling and strong standard networking support.

## Decision
Implement the API and domain services in Go, favoring `net/http`, Chi, pgx, `slog`, `context.Context` and small interfaces.

## Consequences
The service has a small runtime footprint and clear concurrency model. Contributors must keep dependencies limited and avoid framework-driven domain coupling.
