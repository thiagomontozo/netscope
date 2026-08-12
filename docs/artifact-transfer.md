# Artifact transfer

Artifacts are generic `PCAP`, `RAW_EVIDENCE`, `JOB_INPUT`, `JOB_OUTPUT` or
`REPORT` objects with direction, content type, opaque storage key, bounded size,
SHA-256, state and retention metadata. PostgreSQL stores metadata; ObjectStorage
stores bytes. Original filenames are display-only and never form a path.

An authenticated Agent requests a short-lived HMAC transfer token for one
artifact, Agent, organization, job and purpose (`UPLOAD` or `DOWNLOAD`). The
Control Plane rechecks job ownership, direction, state and size before issuing
it. The token does not grant object-storage credentials. Uploads stream through
a private temporary file with a hard byte bound and SHA-256 calculation, become
`AVAILABLE` only after final size/checksum validation and ObjectStorage success,
and otherwise become `FAILED`. Downloads remain bounded and the Agent performs
its own streaming checksum before atomically accepting the temporary file.

Defaults are 1 GiB upload/download and a five-minute token. Deployments should
lower limits and content-type policy for their workloads. Multipart resumability
is deliberately deferred; the domain and state machine permit it later.
