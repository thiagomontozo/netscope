# Continuous Integration

NetScope uses GitHub Actions for deterministic validation on pushes and pull
requests targeting `main`, with an optional manual trigger.

## Control-plane gates

- Backend formatting, module checksum verification, `go vet`, package tests and
  a server build using the Go version declared in `backend/go.mod`.
- Frontend dependency installation from `package-lock.json`, TypeScript project
  build and Vite production bundle using Node.js 22.
- Ordered application of all upward SQL migrations to an ephemeral PostgreSQL
  17 service with stop-on-error behavior.
- Backend and frontend container builds after the language and migration gates
  succeed.

The workflow has read-only repository permissions, pins third-party actions to
reviewed commit SHAs, cancels superseded runs and applies job timeouts. The
PostgreSQL password is an isolated, non-secret value used only by the ephemeral
CI service.

## Safety boundary

CI does not execute diagnostics, packet capture, network discovery, traffic
analysis, vulnerability assessment or external scanner tools. In particular,
it does not invoke Nmap, Zeek, Suricata, TShark, Greenbone/OpenVAS or NetScope
Agent modules. The workflow only validates source, migrations and build
artifacts.

## Branch protection

After the first workflow run, repository administrators should require these
checks before merging into `main`:

- `Backend quality and build`
- `Frontend typecheck and build`
- `PostgreSQL migrations`
- `Container builds`

Keep approval requirements and branch-protection policy in GitHub rather than
embedding privileged write operations in CI.
