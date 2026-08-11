# API

Browser routes use `/api/v1`; agent routes use `/agent/v1`. Browser calls use secure sessions and organization context restored server-side. Agent calls require verified cryptographic identity and are never browser-accessible.

Resources include auth, users, roles, permissions, assets, scopes, agents, modules, jobs, schedules, observations, findings, evidence, vulnerabilities, traffic, PCAP, reports, notifications and audit. SSE at `/api/v1/events` carries progress, agent, notification and finding updates.

Job requests contain a module ID and references plus schema-bound parameters. They never contain a command or shell arguments. Public targets cannot be provided directly.

Errors have a stable code, safe message and request ID. Stack traces and underlying credentials are never returned. List endpoints require pagination, bounded filters and organization predicates when repositories are completed. State-changing endpoints require idempotency or optimistic concurrency where replay is meaningful.

Agent enrollment uses `POST /agent/v1/enroll` with a single-use token and CSR. Authenticated polling uses heartbeat, next, start, result and fail endpoints. Result bodies are size- and item-bounded, job/agent/organization-bound and transition-checked; normalized observations, evidence and vulnerabilities are committed with the terminal job state.

Operational commands include asset create/update/delete; scope create/approve/revoke; user create/disable and role assignment; custom role permission management; schedule create/toggle; module override; job cancellation; agent enrollment/revoke; PCAP upload/download/delete; report generation/download; and raw evidence download.
