# 0017: Versioned Agent Protocol

Status: Accepted

## Context

Implicit request structs make distributed upgrades unsafe and compatibility
opaque.

## Decision

All Agent Protocol messages carry `major.minor` version `1.0`; major mismatch is
incompatible and same-major minor evolution is explicitly evaluated.

## Consequences

Agents and Control Plane can report compatibility before dispatch. Contract
changes require version review and cannot silently change required semantics.
