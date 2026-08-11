# 0013: Use Object Storage for artifacts

## Status
Accepted

## Context
PCAP, reports and raw evidence can be large and sensitive.

## Decision
Use an `ObjectStorage` interface with opaque internal keys and a local private implementation first.

## Consequences
PostgreSQL stays focused on metadata. Retention and authorization must coordinate object and database lifecycle; S3 is a future adapter.
