# Transactional Artifact, Evidence and Observation flow

Agent uploads become `AVAILABLE` only after bounded streaming, byte count,
SHA-256 validation and ObjectStorage success. A result then references the
artifact by stable UUID. The Control Plane locks the job and, in one PostgreSQL
transaction, reserves the receipt, validates provenance, creates Evidence,
creates linked Observations, audits and moves the job to `SUCCEEDED`.

Any metadata failure rolls back all correlated rows. When object bytes were
written but upload metadata finalization fails, compensating deletion removes
the uncommitted object and the artifact becomes `FAILED`. Exact retries are
idempotent; a different payload for an accepted result identity is rejected.
Safe CI integration covers happy path, exact retry, failed artifact and
cross-organization rollback.
