# Agents

Agents are separately deployed workers from `thiagomontozo/netscope-agent`. They connect outbound, making common NAT and firewall deployments simpler.

## Enrollment

An administrator creates a random, short-lived, single-use enrollment token stored only as a hash. A successful registration consumes it atomically and creates an agent identity. The enrollment token is never permanent authentication.

## Trust lifecycle

After enrollment, mTLS or equivalent identity authenticates heartbeat, job polling and result submission. The control plane records the public fingerprint and can revoke or rotate identity. Revoked agents receive no work and cannot submit state.

## Capabilities

An agent reports OS, architecture, version, modules, external tools, network capability, labels and zone. The control plane dispatches only compatible jobs. Declared capability is necessary but not sufficient: scope and user policy still apply.

## Job envelope

An envelope binds job, module, organization, agent, scope, target reference, validated parameters, risk class, nonce, issue time and expiry. A defense-in-depth signature can cover a canonical representation. Agents reject expiry, wrong recipient, unknown module, schema mismatch, replayed nonce and target mismatch.

## State transitions

Only valid compare-and-swap transitions are accepted: queued → assigned → running → succeeded/failed, with cancellation and timeout terminal paths. Result ingestion is idempotent and organization-bound.
