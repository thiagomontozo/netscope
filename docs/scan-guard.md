# Scan Guard

Scan Guard is the mandatory policy decision point for active work. It evaluates the authenticated user, active organization, scope ownership/state/window, environment, module status/risk, public permission, input schema, compatible agent, maintenance window, rate, concurrency, normalized target and bounded timeout.

The result is an allow decision with normalized target and deadline, or a deny decision with a stable code such as `SCOPE_NOT_AUTHORIZED`, `PERMISSION_DENIED`, `AGENT_INCOMPATIBLE`, `RATE_LIMITED` or `INVALID_PARAMETERS`.

## Invariants

- Module executors are unreachable from browser handlers except through job orchestration.
- Job persistence carries the successful decision context.
- Agent envelopes cannot change the scope-derived target.
- Controlled modules cannot be scheduled at unsafe frequency.
- A database failure fails closed; it is not interpreted as authorization.
- Rejections are auditable without recording sensitive parameters.
