# Protocol canonicalization

NetScope Protocol 1.0 signed payloads use RFC 8785 JCS. The implementation is
centralized in `backend/internal/canonicaljson`; handlers and signing services
do not implement ordering or number formatting.

Input must be one valid I-JSON value with unique object names and valid UTF-8.
Numbers are parsed with `json.Number`, checked for finite IEEE-754 binary64
range and emitted using JCS ECMAScript serialization. Decimal meaning is not
truncated or converted to strings. `NaN`, infinities, overflow and nonzero
underflow fail closed. Bare integers outside the interoperable I-JSON safe range
(`±(2^53-1)`) are rejected instead of silently rounded.

Control Plane vectors cover integers, decimals, nested objects, arrays, Unicode
and JobEnvelope payloads. The Agent stores a checksummed snapshot and verifies
the same canonical bytes, SHA-256 and Ed25519 signatures in CI.
