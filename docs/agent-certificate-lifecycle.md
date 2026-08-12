# Agent certificate lifecycle

`agent_certificates` records serial, fingerprint, validity, status and
replacement chain. States are `ACTIVE`, `ROTATING`, `REVOKED`, `EXPIRED` and
`SUPERSEDED`. The Agent detail view reports expiry, days remaining and rotation
state. Default policy is a 90-day certificate, rotation recommendation 14 days
before expiry and a 24-hour transition grace period.

An Agent authenticated by its current certificate generates a new private key
locally and sends only its CSR to `/agent/v1/identity/rotate`. The Control Plane
issues a `ROTATING` certificate. The Agent verifies key pairing, validity and
fingerprint, fsyncs a private staging identity, and atomically swaps directories
with a bounded rollback. `/agent/v1/identity/rotate/confirm` activates the new
certificate and supersedes the prior record. Private keys never leave the
Agent. Administrators can revoke the Agent; its heartbeat, jobs and artifact
authorization then fail database-backed identity checks.

The current internal CA is file-backed. Production must protect its private key
with appropriate secret/key management. HSM, OCSP and automated fleet-wide
rotation scheduling are not claimed.
