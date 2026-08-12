# Evidence

Evidence may reference generic artifact metadata. Artifact content stays in
ObjectStorage and becomes available only after job-scoped authorization,
bounded streaming, final-size and SHA-256 verification. A checksum does not by
itself establish forensic custody.

See [Network Evidence](network-evidence.md) for the full provenance model.
Evidence records module, agent, job, optional vantage, observation time, SHA-256,
size and content type. References identify the technical source type; artifacts
hold opaque object-storage keys. Integrity metadata helps detect unintended
changes but is not a forensic certification or tamper-proof guarantee.

Evidence preserves provenance for a job, optional observation and optional finding. It records source, content type, safe summary, optional structured data, optional storage key, checksum and creation time.

Small normalized evidence can live in PostgreSQL. Large or sensitive artifacts use Object Storage. Keys are generated internally and validated; filenames never become paths. Checksums detect accidental corruption but do not alone establish custody.

`findings.read` does not imply `evidence.raw.read`. Raw PCAP additionally requires `pcap.download`. Access is organization-bound, audited and subject to retention. Evidence summaries should be sufficient for routine review while Technical Evidence gives authorized analysts the source detail.
