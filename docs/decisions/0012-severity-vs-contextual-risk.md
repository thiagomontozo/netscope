# 0012: Separate severity and contextual risk

## Status
Accepted

## Context
CVSS or scanner severity alone does not express organizational priority.

## Decision
Keep severity, priority and confidence independent; derive priority from visible contextual factors.

## Consequences
Analysts can understand prioritization. The engine must document factor changes and audited overrides.
