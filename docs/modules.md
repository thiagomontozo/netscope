# Modules

Every `ModuleDefinition` now declares protocol version, supported platforms,
parameter schema version and result schema version in addition to identity,
risk, environment, capability and timeout. Diagnostic Profiles are allowlists of
module IDs; neither profiles nor jobs contain shell commands, CLI strings or
arbitrary flags.

A module is a versioned, typed capability. It declares category, `PASSIVE`/`SAFE_ACTIVE`/`CONTROLLED_ACTIVE` risk, supported environments, required capabilities, timeout, input schema, result schema and enabled state.

The registry associates each definition with a parameter validator, executor boundary and result parser. Code calls the registry; tool-specific branching does not leak through the domain.

## Built-in catalog foundation

- Safe active: `network.ping`, `network.route`, `network.dns`, `network.tcp`, `network.http`, `network.tls`.
- Controlled active: `nmap.discovery`, `nmap.services`, `vulnerability.greenbone`, `performance.iperf3`.
- Passive: `traffic.tshark`, `traffic.zeek`, `security.suricata`.

Nmap profiles are predefined and bounded. HTTP is HEAD/GET only. TCP sends no payload. TShark accepts presets, not arbitrary filters. iperf requires an approved destination endpoint. The API never accepts command, shell or free-form arguments.

Adapters produce normalized observations and evidence. Parser failure produces an inconclusive outcome with diagnostic provenance; it never silently reports health.
