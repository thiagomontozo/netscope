# Job signing

NetScope keeps HTTPS and mTLS mandatory and adds Ed25519 signatures as a second
authorization boundary. The active private key is loaded only from
`NETSCOPE_JOB_SIGNING_KEY_FILE` (PKCS#8 PEM); its stable, non-secret identifier
comes from `NETSCOPE_JOB_SIGNING_KEY_ID`. Private bytes are never stored in
PostgreSQL, returned by an API, or logged.

Enrollment distributes the key ID, algorithm, base64 public key, SHA-256
fingerprint and issue time. A signed envelope carries `signingKeyId`,
`signatureAlgorithm` and `signature`. The Agent selects that exact trusted key,
canonicalizes the protected fields, verifies Ed25519, and only then reaches the
module registry. Expired, replayed, misaddressed, unsigned-required and modified
jobs fail closed. `NETSCOPE_REQUIRE_SIGNED_JOBS=true` prevents unsigned delivery
when signing is unavailable.

NetScope Canonical JSON v1 lexically sorts object keys, preserves array order,
uses standard JSON string escaping and removes insignificant whitespace. It
covers protocol/job/organization/agent/module/scope/target/parameters/risk/
authorization/time/timeout/nonce and optional asset/service identities. The
Protocol 1.0 test vectors lock canonical bytes, SHA-256 and Ed25519 signature.
The current implementation supports Ed25519 only and one active Control Plane
signing key; fields prepare a later coordinated key rotation.
