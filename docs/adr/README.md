# Architecture decision records

Accepted architectural decisions live here. Each record preserves the reason behind one costly-to-reverse boundary or direction; superseded records remain in the index and repository.

| ADR | Status | Governs | Relation |
| --- | --- | --- | --- |
| [ADR-001](001-rust-api-and-wire-boundary.md) | Accepted | WISP-004 library API and CLI serialization boundary | None |
| [ADR-002](002-filesystem-snapshot-boundary.md) | Accepted | WISP-004 filesystem containment and input-stability claims | None |

Do not merge the Rust API and JSON transport failure types without a new ADR.

Do not claim an atomic or race-free filesystem snapshot without a new ADR.
