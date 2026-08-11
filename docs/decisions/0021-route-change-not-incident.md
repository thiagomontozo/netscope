# 0021: Route change is not an incident by default

Status: Accepted

## Context

Normal routing, reply suppression and vantage differences can alter observed
hops without service impact.

## Decision

Store route change as a Change Observation with confidence. Create or link an
Incident only through explicit operator action or additional deterministic
impact evidence.

## Consequences

The product avoids noisy alarmism while retaining path history for investigation.
