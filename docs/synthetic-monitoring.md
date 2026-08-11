# Synthetic Monitoring

Schedules are limited to safe DNS, TCP, HTTP, TLS and supported ping checks.
Continuous Nmap or vulnerability scanning is not enabled by default. Schedule
creation preserves scope validity, public-target permission and minimum
frequency. Parameters are stored as a validated module object, never a command
or free-form CLI argument. Every generated job is re-authorized by ScanGuard.

Normalized `MonitorSample` history records availability, latency, packet loss,
DNS duration, TCP connection duration, TLS expiry, HTTP duration and HTTP status
per asset, service and vantage point. A lightweight operational baseline stores
sample count, observed range and a typical range over a declared window.

Baseline language is descriptive: “above recent baseline,” not “attack” or
AI-derived anomaly. Sparse, stale or conflicting samples produce an
inconclusive comparison. NetScope does not implement ML in this model.
