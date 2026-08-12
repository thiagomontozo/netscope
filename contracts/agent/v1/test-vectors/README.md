# Protocol 1.0 test vectors

Every key and signature in this directory is **TEST ONLY**. The Ed25519 seed is
the published RFC 8032 test seed and must never be used by a deployment.

The v0.2.1 vectors use RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8
output, SHA-256 over the canonical bytes, and Ed25519 over those same bytes.
Objects are ordered by UTF-16 property-name code units; array order and Unicode
strings are preserved; whitespace is removed. Finite I-JSON binary64 numbers
use deterministic ECMAScript serialization. Decimal values remain numbers;
`NaN`, infinities, overflow, underflow, duplicate names and multiple JSON
values are rejected. Bare integers are limited to the interoperable I-JSON
range `±(2^53-1)`.

Each generated vector contains input JSON, canonical text, SHA-256, algorithm,
key ID, test public key, signature and expected result. Regenerate from
`backend` with `go run ./cmd/contract-vectors`.

The Agent vendors this directory with `contract-manifest.sha256`; synchronized
changes are reviewed in both repositories and create no runtime dependency.
