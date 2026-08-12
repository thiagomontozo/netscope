# Agents

Agent trust status combines Protocol/contract/capability versions, mTLS
certificate history, expiry/rotation, named Ed25519 job trust, heartbeat and
artifact transfer state. Revocation blocks heartbeat, jobs, rotation and
artifact authorization through the shared database identity middleware.

Agents implement [Protocol v1](agent-protocol.md), connect outbound and report a
versioned capability manifest. The Control Plane stores protocol compatibility,
heartbeat health, slots and vantage association. Centralized grace thresholds
move agents through online, degraded and offline states; a single late heartbeat
does not imply outage. Enrollment tokens are never durable credentials.

Agents are separately deployed workers from `thiagomontozo/netscope-agent`. They connect outbound, making common NAT and firewall deployments simpler.

## Enrollment

An administrator creates a random, short-lived, single-use enrollment token stored only as a hash. A successful registration consumes it atomically and creates an agent identity. The enrollment token is never permanent authentication.

## Trust lifecycle

After enrollment, mTLS authenticates heartbeat, job polling and result submission. Enrollment consumes a token atomically, validates a PKCS#10 CSR, signs a 90-day client certificate using the externally mounted agent CA, records its SHA-256 fingerprint and returns only public certificate material. Revoked or expired identities receive no work and cannot submit state.

The production Compose overlay exposes the Go HTTPS listener directly for agents and configures the frontend proxy to verify the backend server CA. Browser routes accept no client certificate; agent routes additionally require a verified and database-active agent fingerprint.

## Capabilities

An agent reports OS, architecture, version, modules, external tools, network capability, labels and zone. The control plane dispatches only compatible jobs. Declared capability is necessary but not sufficient: scope and user policy still apply.

## Job envelope

An envelope binds job, module, organization, agent, scope, target reference, validated parameters, risk class, nonce, issue time and expiry. A defense-in-depth signature can cover a canonical representation. Agents reject expiry, wrong recipient, unknown module, schema mismatch, replayed nonce and target mismatch.

## State transitions

Only valid compare-and-swap transitions are accepted: queued → assigned → running → succeeded/failed, with cancellation and timeout terminal paths. Result ingestion is idempotent and organization-bound.
