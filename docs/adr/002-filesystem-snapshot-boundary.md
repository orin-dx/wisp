# ADR-002: Bound filesystem claims to observed reads

Status: Accepted

## Context

WISP-004 resolves selected plan/spec paths beneath a workspace, rejects detected escapes, and rereads both sources before publishing a result. Path canonicalization and rereads do not create an atomic snapshot if another process changes filesystem paths concurrently.

## Decision

The MVP rejects observed path escapes and input changes, but does not promise race-free containment or an atomic workspace snapshot. Hostile concurrent filesystem replacement remains outside the threat model.

## Options considered

- Claim an atomic snapshot because the operation canonicalizes paths and rereads bytes; those checks cannot prove that paths remained bound to the same objects.
- Add a capability-filesystem dependency now because it would broaden the implementation and still require a separately stated snapshot guarantee.

## Consequences

The handoff is suitable for bounded local artifact validation, not as a security boundary against a hostile process sharing write access. Any stronger promise requires a revised threat model, implementation, and adversarial tests.
