# Trusted Agent communication threat model

This model reduces risk; it does not claim complete compromise resistance.

| Threat | Control | Residual limitation |
|---|---|---|
| Stolen enrollment token | short TTL, SHA-256 at rest, row lock, single use | theft before use can enroll once |
| MITM | HTTPS, pinned/server CA validation and mTLS | compromised CA remains trusted |
| Job manipulation or replay | Ed25519, expiry, Agent/org binding, nonce cache | Agent restart loses the bounded in-memory nonce cache; completed job state still rejects results |
| Protocol downgrade | explicit major compatibility and signed policy | legacy unsigned mode must be visibly enabled |
| Stolen Agent private key | local 0600 material, rotation and revocation | host compromise can use the key until revoked |
| Compromised Agent | scoped jobs/artifacts, Scan Guard, idempotent import | authorized evidence can still be falsified by that Agent |
| Compromised Control Plane | separated signing/CA secret files and audit | issuer compromise is a high-impact trust failure |
| Artifact tampering | scoped tokens, streaming size/SHA-256 verification | SHA-256 is integrity, not forensic custody |
| Malicious filename/path | opaque generated storage keys; filename metadata only | object-store implementation must preserve key validation |
| Oversized artifact/DoS | hard byte limits, short token TTL, bounded temporary files | production-scale load testing is pending |
| Stale certificate | expiry visibility, rotation, supersession/revocation | OCSP is not implemented |
