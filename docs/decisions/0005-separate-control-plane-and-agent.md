# 0005: Separate control plane and agent

## Status
Accepted

## Context
Network tools require privileges and placement that the public-facing API must not have.

## Decision
Keep agents in a separate repository and deployment. The control plane sends typed jobs; agents execute approved adapters.

## Consequences
The API container excludes scanners and elevated privileges. Version compatibility and job schemas require deliberate management.
