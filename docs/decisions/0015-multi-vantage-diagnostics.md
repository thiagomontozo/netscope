# 0015: Multi-vantage diagnostics

Status: Accepted

## Context

A single monitoring location cannot distinguish service-wide failure from a
path-, site- or sensor-specific condition.

## Decision

Store explicit organization-scoped Vantage Points and attach them to jobs,
evidence, route history and monitor samples. Compare normalized observations
without converting disagreement into a global outage.

## Consequences

Operators see affected locations and conflicting evidence. Scheduling and
queries gain an additional isolation key and must validate agent association.
