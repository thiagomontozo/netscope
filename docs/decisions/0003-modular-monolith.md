# 0003: Start as a modular monolith

## Status
Accepted

## Context
NetScope has many domains but does not yet justify distributed operational complexity.

## Decision
Deploy one control-plane service with explicit internal module boundaries and dependency injection.

## Consequences
Transactions and deployment remain simple. Boundaries must be enforced in code so future extraction remains possible.
