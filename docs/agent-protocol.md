# NetScope Agent Protocol v1

The normative machine-readable contract is in `contracts/agent/v1` and uses
`protocolVersion: "1.0"`. Browser clients cannot call the Agent API.

Endpoints:

- `POST /agent/v1/enroll` — single-use token, identity metadata, CSR and initial
  capability summary; returns organization/agent IDs, CA identity and the new
  agent certificate.
- `POST /agent/v1/heartbeat` — versioned liveness, slots, running jobs,
  capability hash and bounded health summary.
- `POST /agent/v1/capabilities` — complete module/tool/artifact manifest.
- `GET|POST /agent/v1/jobs/next` — one Authorized Scope-derived envelope.
- `POST /agent/v1/jobs/:id/start` — `ASSIGNED` to `RUNNING`.
- `POST /agent/v1/jobs/:id/result` — idempotent normalized result import.
- `POST /agent/v1/jobs/:id/fail` — stable failure code and safe summary.
- `GET /agent/v1/jobs/:id/cancellation` — cancellation/status check.
- `POST /agent/v1/evidence` — idempotent evidence metadata registration.

All post-enrollment endpoints require verified mTLS and bind the certificate
fingerprint to one active organization/agent. Envelopes contain no shell, CLI or
arbitrary argument fields. See [Agent compatibility](agent-compatibility.md).
