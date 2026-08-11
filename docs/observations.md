# Observations

Observations are immutable time-bound facts. Change Observations separately
record service, DNS, certificate, route, HTTP-pattern or capability changes with
previous/current structured values and confidence. A change does not become an
incident automatically. Multi-vantage disagreement produces an attention or
inconclusive explanation rather than overwriting individual observations.

An Observation is a factual, time-bound statement produced by a known module and job. It stores category, normalized status, severity, confidence, title, summary, meaning, impact, suggested action, observation time, evidence count and optional raw reference.

Good language separates layers:

- Observed: “TCP port 443 accepted the connection.”
- Meaning: “The HTTPS service is reachable from this sensor.”
- Evidence: “TCP connection completed in 18 ms.”

It must not conclude that the server is secure. Missing, contradictory or failed collection uses `INCONCLUSIVE` with an explicit explanation. Observation immutability preserves what was known at the time; newer evidence creates another observation.
