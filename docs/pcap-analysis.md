# PCAP Analysis

## Workflow

Upload → validate metadata/size → private storage → analysis job → TShark, Zeek and/or Suricata → normalization → correlation → report.

Uploads are organization-bound, size-limited, checked for recognized PCAP/PCAPNG magic, checksummed while streaming and assigned opaque storage keys. Original names are metadata only and never become response headers or paths. Files are never served by a public static path. Download, deletion and analysis require distinct permissions and audit events.

PCAP defaults to seven-day retention because it can contain credentials, personal data and sensitive communications. An organization policy can override the duration; the retention worker removes expired objects and records tombstone/audit metadata. No real PCAP belongs in Git. Mobile UI may show summaries but is not intended for full packet analysis.
