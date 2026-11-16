---
"wisp-model": minor
"wisp-schema": minor
"wisp-artifacts": minor
"wisp-cli": minor
---

Add the spec artifact commands and the read-only implementation handoff

- `wisp artifact validate|persist|get|status` validates, atomically persists, and reports the Git status of a canonical `spec@1`.
- `wisp brief implement` checks one selected plan/spec chain and returns the exact tasks, criteria, source digests, and gaps as one bounded `implementation-context@1` JSON result.
- The library returns typed Rust errors; only the CLI converts them to the wire envelope.

Action: the controlled value evaluation is still pending, so no reduction in session cost is claimed.
