# Multi-Vantage Diagnostics

A Vantage Point is the logical place from which an observation was made: an
agent, branch, site, datacenter, DMZ, external sensor or cloud location. It is
organization-scoped and records environment, site, zone, labels and active
state. A vantage may be tied to exactly one current agent.

Diagnostic Runs group safe module jobs for one asset/service under profiles such
as `CONNECTIVITY`, `WEB_SERVICE`, `DNS`, `TLS`, `NETWORK_PATH`,
`PUBLIC_SERVICE_HEALTH` and `FULL_SAFE_DIAGNOSTIC`. Profiles contain module IDs,
never commands or flags. Each job still passes ScanGuard independently.

Comparison is deterministic. Agreement from multiple direct responses can raise
confidence. Conflicting results produce a location/path-specific explanation,
not “service down.” Missing or timed-out observations remain inconclusive. The
Control Plane stores per-vantage monitor samples so availability, latency, loss,
DNS/TCP/HTTP duration, TLS expiry and HTTP status can be compared over time.
