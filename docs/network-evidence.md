# Network Evidence

Network Evidence is the provenance-bearing record behind an observation,
finding, correlation or incident conclusion. It answers what was observed, how,
from which vantage point, when, by which module and agent, with what confidence,
and whether raw technical material exists.

`Evidence` holds the safe summary and structured result. `EvidenceReference`
links it to typed sources such as DNS responses, TLS metadata, route hops, HTTP
transactions, Nmap results, Zeek/Suricata events or vulnerability evidence.
`EvidenceArtifact` points to private object storage; large output and PCAP never
belong in PostgreSQL.

Integrity metadata includes SHA-256, byte size, media type, module, agent, job,
vantage point and timestamps. Evidence integrity metadata helps detect
unintended artifact changes. It is not a formal chain of custody, forensic
certification, proof of admissibility or a claim that data is tamper-proof.

Raw evidence requires `evidence.raw.read`; PCAP download remains separately
protected. Summaries must not expose secret material or replace the permission
check on artifact retrieval.
