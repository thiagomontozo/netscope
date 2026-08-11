# Route History and Comparison

`RouteSnapshot` stores an asset/service destination, job and vantage point with
ordered `RouteHop` records. Each hop retains address, hostname, latency samples
and timeout state. `RouteComparison` references two immutable snapshots and
reports `UNCHANGED`, `CHANGED`, `PARTIALLY_CHANGED` or `INCONCLUSIVE`.

The deterministic comparator identifies the first address-level divergence,
different path length, or the first timeout-limited comparison. Latency samples
remain available for display but do not by themselves establish causality.

A route change produces a Change Observation. It is not an incident by default:
routing can change normally, intermediaries can suppress replies, and vantage
points can observe different valid paths. Incident correlation requires
additional temporal and service-impact evidence.
