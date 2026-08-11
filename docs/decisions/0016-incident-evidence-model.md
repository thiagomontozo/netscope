# 0016: Incident evidence model

Status: Accepted

## Context

Findings do not represent an entire operational investigation or its timeline.

## Decision

Model Incident, IncidentEvent, typed links, evidence roles and an evidence
report separately from Finding. Root-cause status is explicit and independent.

## Consequences

Investigations can combine operational and security evidence without inventing
causality. Operators must curate evidence roles and lifecycle transitions.
