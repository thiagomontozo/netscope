# NetScope Agent Protocol v1

Protocol version: `1.0`.

These JSON Schemas are the machine-readable contract between the NetScope
Control Plane and separately deployed NetScope Agents. Browser clients must
never use `/agent/v1`.

## Compatibility

The version is `major.minor`. A different major version is incompatible. The
same major version can evolve compatibly: minor releases may add optional
fields, enum values only where documented, or new endpoints. Senders must not
omit required fields. Receivers reject unknown fields in v1 security-sensitive
messages so unsupported behavior is explicit rather than silently accepted.

The Control Plane stores the reported agent and protocol versions and derives
`COMPATIBLE`, `UPGRADE_RECOMMENDED`, `INCOMPATIBLE`, or `UNKNOWN`. Module
contracts independently declare parameter and result schema versions.

## Transport and trust

Enrollment uses a short-lived, single-use token only once. The response issues
an agent-specific mTLS certificate. Subsequent calls require that certificate;
the token is never returned. Agents initiate all connections. The Control Plane
does not open a shell or administrative connection to an agent.

Job envelopes contain only a module identity, an Authorized Scope-derived
target and schema-validated parameters. They never contain shell commands, raw
CLI strings or arbitrary arguments. Ed25519 signing fields are reserved in v1,
but signing is not active until a deployment configures a protected private key
and distributes its public trust key during enrollment. mTLS and database-backed
authorization remain mandatory regardless of envelope signing.

Signed deployments set the optional triplet `signingKeyId`,
`signatureAlgorithm=Ed25519` and `signature`; the Agent selects only the named
trusted key. NetScope Canonical JSON v1 signs a deterministic object containing
the security-relevant envelope fields documented in `docs/job-signing.md`.
Object keys use lexical order, arrays retain order, strings use JSON escaping
and insignificant whitespace is removed. The checked-in TEST ONLY vectors are
the cross-repository authority for canonical bytes, SHA-256 and signature.

## Retry and idempotency

`JobResult` supplies `resultIdentity` and `resultVersion`. The Control Plane
accepts one result receipt per job. Repeating the same identity/version and
payload checksum is a successful no-op; changed content or a different result
for an already completed job is rejected.
Evidence manifests use stable evidence IDs. Failures and cancellation checks
are safe to retry, subject to the job state machine.

## Schemas

- `enrollment.schema.json`: enrollment request and response.
- `heartbeat.schema.json`: liveness and bounded health summary.
- `capabilities.schema.json`: module/tool capability manifest.
- `job-envelope.schema.json`: authorized work delivered to one agent.
- `job-result.schema.json`: normalized observations, metrics and evidence.
- `job-failure.schema.json`: stable failure codes without stack traces.
- `job-cancellation.schema.json`: cancellation status polling.
- `evidence-manifest.schema.json`: evidence provenance and integrity metadata.
- `artifact-manifest.schema.json`: generic artifact metadata and integrity.
- `errors.schema.json`: stable API error envelope.
