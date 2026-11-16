# ADR-001: Keep the Rust API and JSON failure envelope at separate boundaries

Status: Accepted

## Context

WISP-004 exposes implementation-context assembly as a Rust library operation and as a CLI JSON protocol. Returning the serialized failure envelope from the library would couple Rust callers to the CLI contract and make ordinary Rust error handling awkward.

## Decision

The library accepts one typed `ImplementationSelection` containing the selector kind and ID, and returns `ImplementationContextError` on failure. The CLI converts that error to the versioned `implementation-context@1` failure envelope. The success result remains the versioned handoff model because consumers exchange that data contract.

## Options considered

- Pass a selector enum and a separate ID because that permits invalid pairings and spreads their validation across call sites.
- Return `ImplementationContextFailure` directly from the library because that makes the Rust API depend on a transport representation.

## Consequences

Rust callers can use `?` and match typed fields without parsing JSON protocol objects. The CLI remains responsible for stable JSON serialization and exit behavior. The library API and the wire contract evolve independently where their semantics differ.

Enforced by: the public library signature, strict Rust compilation, and CLI integration tests for the JSON failure envelope.
