# Traffic Analysis

Traffic analysis normalizes `TrafficSummary`, `ProtocolStatistic`, `ConnectionObservation` and security observations rather than exposing tool interfaces wholesale.

Zeek contributes connection, DNS, HTTP, TLS/SSL, SSH and protocol metadata. Suricata contributes EVE alerts with signature, category, severity, endpoints and timestamp. TShark contributes bounded PCAP metadata and selected fields through presets.

PCAP analysis is passive but the artifact remains highly sensitive. Imported alerts retain their source semantics; a Suricata alert is evidence of a rule match, not proof of compromise. High-volume metadata sits behind repository boundaries so ClickHouse can be adopted later.
