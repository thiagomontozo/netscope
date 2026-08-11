# Evidence

Evidence preserves provenance for a job, optional observation and optional finding. It records source, content type, safe summary, optional structured data, optional storage key, checksum and creation time.

Small normalized evidence can live in PostgreSQL. Large or sensitive artifacts use Object Storage. Keys are generated internally and validated; filenames never become paths. Checksums detect accidental corruption but do not alone establish custody.

`findings.read` does not imply `evidence.raw.read`. Raw PCAP additionally requires `pcap.download`. Access is organization-bound, audited and subject to retention. Evidence summaries should be sufficient for routine review while Technical Evidence gives authorized analysts the source detail.
