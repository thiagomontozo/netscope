# Findings

A Finding is reviewable action; an Incident is an investigation container.
Findings can be linked into an incident timeline without changing severity,
priority or confidence. Correlations must expose inputs, deterministic rules,
reasons and evidence. Vulnerability, open service, IDS alert or high CVSS alone
never proves compromise.

A Finding is a reviewable conclusion or required action derived from one or more observations. It includes independent severity, contextual priority and confidence, plus affected asset, description, remediation and lifecycle.

Statuses are `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `ACCEPTED` and `FALSE_POSITIVE`. Changes record actor, time and audit event. Resolution does not delete source evidence.

Finding detail answers what was observed, what it means, why it matters, suggested action and “Why am I seeing this?”. The explainability chain lists modules, evidence and enrichment that produced it. A detected CVE or IDS alert does not by itself assert compromise.
