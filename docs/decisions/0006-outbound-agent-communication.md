# 0006: Use outbound agent communication

## Status
Accepted

## Context
Agents commonly run behind NAT and restrictive firewalls.

## Decision
Agents initiate authenticated HTTPS heartbeat and polling connections to the control plane.

## Consequences
Deployment needs no inbound agent port. Poll latency and server load require bounded backoff and later transport options.
