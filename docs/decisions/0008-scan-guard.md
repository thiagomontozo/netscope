# 0008: Centralize active execution policy in Scan Guard

## Status
Accepted

## Context
Scattered checks are easy for adapters or new modules to bypass.

## Decision
Require one fail-closed Scan Guard decision before creating any active job.

## Consequences
Authorization is consistent and auditable. New policy inputs must integrate without turning the guard into tool-specific logic.
