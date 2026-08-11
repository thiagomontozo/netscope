# 0018: Machine-readable agent contracts

Status: Accepted

## Context

Narrative API examples do not prevent field drift or unsafe free-form work.

## Decision

Publish Draft 2020-12 JSON Schemas under `contracts/agent/v1` and keep Go API
types aligned with them. Security-sensitive objects reject unknown fields.

## Consequences

Implementations share a reviewable handoff. Schema validation in agents remains
required; generated code may be introduced later without changing the contract.
