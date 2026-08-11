# 0004: Use PostgreSQL as source of truth

## Status
Accepted

## Context
Authorization, state transitions, correlation and audit need transactional consistency.

## Decision
Store control-plane records in PostgreSQL using SQL migrations and pgx.

## Consequences
Organization isolation and lifecycle updates can be transactional. High-volume telemetry may later move behind repositories to ClickHouse.
