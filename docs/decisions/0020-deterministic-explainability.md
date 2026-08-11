# 0020: Deterministic explainability

Status: Accepted

## Context

Analysts need to know why a conclusion or priority exists without opaque AI.

## Decision

Correlations expose inputs, deterministic rules, human-readable reasons,
evidence references and confidence. No LLM participates in v0.1 conclusions.

## Consequences

Explanations are stable and reviewable. Rules require deliberate domain changes
and cannot infer facts absent from source evidence.
