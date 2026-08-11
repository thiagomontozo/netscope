# PCAP Analysis

## Workflow

Upload → validate metadata/size → private storage → analysis job → TShark, Zeek and/or Suricata → normalization → correlation → report.

Uploads are organization-bound, checksummed and assigned opaque storage keys. Original names are display metadata only. Files are never served by a public static path. Download, deletion and analysis require distinct permissions and audit events.

PCAP defaults to short retention because it can contain credentials, personal data and sensitive communications. Deletion removes the object and records tombstone metadata according to policy. No real PCAP belongs in Git. Mobile UI may show summaries but is not intended for full packet analysis.
