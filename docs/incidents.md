# Incidents and Timeline

An Incident is an operational investigation, not a synonym for a Finding. It
can join assets, services, agents, jobs, diagnostic runs, observations, findings
and evidence while preserving the lifecycle `OPEN`, `INVESTIGATING`,
`MONITORING`, `RESOLVED`, `CLOSED`.

Root cause is independently `UNKNOWN`, `SUSPECTED`, `IDENTIFIED` or
`INCONCLUSIVE`. Closing an incident does not automatically identify a root
cause. Incident events form a chronological timeline of protocol symptoms,
route/certificate changes, agent availability, findings, diagnostics and
operator notes. Every event retains source, status and confidence.

Evidence is explicitly classified as `KEY_EVIDENCE`, `SUPPORTING_EVIDENCE` or
`CONTEXT`. The Incident Evidence Report summarizes affected assets/locations,
symptoms, vantage results, protocol findings, security observations, timeline,
confidence, limitations and next actions. It must state when root cause remains
unknown or inconclusive and must never manufacture one.
