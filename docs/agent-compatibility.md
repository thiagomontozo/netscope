# Agent Compatibility

The Control Plane stores agent version, protocol version and capability
manifest. Compatibility states are `COMPATIBLE`, `UPGRADE_RECOMMENDED`,
`INCOMPATIBLE` and `UNKNOWN`.

Protocol versions use `major.minor`. Different majors are incompatible. The
same major permits compatible minor evolution; a sender cannot omit required
fields, and v1 receivers reject unknown fields in security-sensitive requests.
An agent reporting a newer minor version is marked upgrade recommended until
the Control Plane understands that evolution.

Compatibility does not grant capability. ScanGuard separately verifies module
state, required capabilities, environment, scope, user permission and policies.
Heartbeat state uses centralized interval, degraded grace and offline thresholds;
one late heartbeat does not mark an agent offline.
