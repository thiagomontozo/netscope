# Database

Migration `000003_network_evidence_incidents_protocol` adds VantagePoint,
NetworkService, DiagnosticRun/Profile, Incident/Event/Links/Evidence/Report,
RouteSnapshot/Hop/Comparison, MonitorSample, OperationalBaseline,
ChangeObservation, evidence provenance/artifacts/references, agent compatibility
and idempotent result receipts. Published migrations remain unchanged. New
tables carry `organization_id`; repositories and handlers include it in reads
and relationship creation.

PostgreSQL is the v0.1 source of truth. The initial migration defines organizations; user identity, sessions, MFA and RBAC; scopes and assets; agents and enrollment; modules, jobs and schedules; observations, findings and evidence; vulnerabilities and enrichment; traffic, PCAP, reports, retention, notifications and audit.

Relevant tables carry `organization_id` and indexes begin with it. Repository methods accept the active organization and include it in every read, update and delete predicate. Cross-organization foreign-key integrity can later be strengthened with composite keys; application authorization must already enforce isolation.

Opaque tokens are hash-stored. MFA and external secrets are encrypted at the application layer. JSONB holds typed schemas, bounded parameters, structured evidence and transparent risk factors—not unconstrained domain state.

Transactions protect enrollment token consumption, job state transitions, finding lifecycle and retention deletion. ClickHouse is not required; future traffic/probe repositories can move high-volume history behind interfaces while PostgreSQL retains control-plane truth.
