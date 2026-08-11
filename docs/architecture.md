# Architecture

## Context

NetScope is a modular monolith: one Go deployment owns policy and transactional workflows while React provides the analyst workspace. PostgreSQL is the source of truth. Large sensitive artifacts use an opaque-key Object Storage boundary.

## Control plane boundaries

- Identity: organizations, users, sessions, MFA, roles and permissions.
- Authorization: Authorized Scope, Scan Guard and maintenance/rate/concurrency policies.
- Execution: module registry, scheduler, job orchestrator and transport.
- Knowledge: assets, observations, findings, evidence, vulnerabilities, traffic and correlation.
- Operations: agents, reports, notifications, retention and audit.

Dependencies point toward the domain. HTTP, pgx, local or S3-compatible storage, and HTTPS polling are adapters. Small interfaces keep a future NATS JetStream transport or ClickHouse history store from entering core policy decisions.

## Data and event flow

1. A browser submits a module ID, scope ID, asset ID, agent ID and bounded parameters.
2. The API restores the organization from the authenticated session; it never trusts an organization ID in the body.
3. Scan Guard resolves and checks the approved scope, policy, module and compatible agent.
4. A transactional job is queued with the normalized target and immutable authorization context.
5. An outbound agent requests work using strong identity and receives a short-lived envelope.
6. Results are normalized into observations and evidence, then optionally into findings and correlations.
7. SSE communicates state changes without coupling domain services to HTTP.

## Scaling path

Keep PostgreSQL and HTTPS polling for v0.1. Introduce NATS only behind `JobTransport`. High-volume probe history and traffic metadata can later move behind repositories to ClickHouse. Neither is a current runtime dependency.
