# Security Model

Protocol 1.x trusted communication adds named Ed25519 job signatures, explicit
no-downgrade policy, bounded replay checks, purpose-scoped artifact tokens,
streaming integrity and certificate replacement history on top of mandatory
mTLS, Authorized Scope and Scan Guard.

Protocol v1 adds explicit compatibility, result idempotency and target-context
binding without weakening mTLS, Authorized Scope or ScanGuard. The Agent API
rejects unknown request fields and mismatched protocol/job/agent/module IDs.
Failure codes are bounded and never include stack traces. Ed25519 job signing is
an inactive interface until protected key configuration and trust distribution
are completed; documentation does not claim it is currently active.

## Positioning and trust

NetScope supports diagnostics, monitoring and authorized assessment. It assumes browsers, agents, uploaded files, scanner output and network responses are untrusted. The control plane is the policy authority; agents are constrained executors, not administrative peers.

## Identity

Users authenticate with Argon2id-protected passwords and revocable opaque sessions. Privileged roles require TOTP MFA. Session validation must re-check user activity so disabling a user invalidates existing access. MFA values, recovery codes, passwords and session values are never logged.

Agents enroll once with a short-lived, single-use token and locally generated CSR. Durable access uses a CA-signed mTLS identity checked against the active database fingerprint. Revocation and fingerprint visibility are enforced. Agent private keys never enter control-plane storage.

## Authorization

Every query includes organization ownership. Resource lookup is `organization_id + id`, never an ID followed by a post-fetch check. RBAC gates user operations; raw evidence, PCAP actions and public assessments have explicit permissions. Scan Guard is mandatory for active execution.

## Secrets and artifacts

Application-layer encryption protects MFA and external provider secrets, using a master key supplied by an environment or secret manager. PCAP and raw artifacts use internal opaque keys, restrictive filesystem permissions, retention and separate authorization. Original filenames are metadata only.

## Web controls

Production session cookies are HttpOnly and Secure with appropriate SameSite behavior. State-changing endpoints require CSRF protection when cookie authentication is completed. API errors do not expose stack traces. Reverse proxy headers add content-type, referrer and content-security protections.

## Logging

Structured logs may include request, organization, user, job and agent identifiers. They exclude authorization values, passwords, MFA, cookies, enrollment tokens, private keys, scanner credentials, full PCAP and full raw evidence.
