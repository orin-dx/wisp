# Implementation Handoff MVP

**Status:** Core library, CLI, and optional Claude/AGY and Codex consumption are implemented in the current worktrees; `implementation-context@1` has immutable upstream provenance. Controlled value evaluation remains pending. No release or performance result is implied.

## Outcome

Given a persisted plan and an explicit batch or task selection, Wisp verifies the governing spec relationship and returns exact implementation context with source digests and explicit gaps. Smith retains code inspection, implementation, review, and independent verification. This pilot uses a distinct `wisp handoff implement` command; the existing architecture reserves `wisp brief implement` for the later code-aware M3 briefing.

The first value claim is removal of duplicated mechanical preparation and detection of known handoff inconsistencies. Reduced session cost, fewer parses, and better implementation outcomes are hypotheses to measure, not established benefits.

## Delivered core

- Read only the selected plan, its governing spec, and metadata necessary for this handoff.
- Validate pinned `plan@1` and `spec@1` shapes, identities, paths, references, and raw-byte SHA-256.
- Project exact selected tasks and criteria with purpose, scope, non-goals, and declared API context when present.
- Return one versioned JSON result through the library and CLI.
- Keep the transient response contract separate from canonical artifact schemas and storage.

No SQLite, cache, watcher, daemon, Monokl query, Michi renderer, MCP transport, embedding, hook, arbitrary shell execution, automatic approval, commit, or release belongs in this slice. Do not create every proposed architecture crate; add the operation to the existing model/schema/artifact/CLI layers first.

## Ownership and handoffs

| Boundary | Producer | Consumer | Responsibility |
| --- | --- | --- | --- |
| Governing spec | Scribe or repository owner | Navigator and Wisp | Required behavior; caller retains review/approval evidence |
| Persisted plan | Navigator or repository owner | Wisp | Explicit tasks, criteria, paths, and the source spec hash |
| Implementation context | Wisp | Smith | Source-backed checks and exact projection, not execution approval |
| Implementation evidence | Smith and project checks | Independent reviewer/gate | Current files, commands, terminal results, and coverage gaps |
| Experiment record | Fixture runner | Maintainer; later Prism/Lumen | Actual run evidence with fixed inputs, never synthetic success |

Existing project-artifact schemas remain immutable and owned by agent-plugins. `implementation-context@1` is authored there and its Wisp copy is pinned by source revision and byte digest. Keep that revision available in upstream history. Do not introduce a contracts repository, shared package, or duplicate schema definitions for this pilot.

Wisp does not establish that a plan was approved, that prerequisites finished, that declared files cover all affected code, or that commands are safe. The caller checks those conditions using its current workflow and authorization boundary.

## Proposed invocation

```bash
wisp handoff implement --workspace . --plan docs/projects/SPEC-001.json --batch B1
```

This command is implemented. `--plan` is a workspace-relative path, not an inferred plan ID. Exactly one selector is required: `--batch` for a declared batch or `--task` for one task. The implementation preserves plan order and does not infer a scheduler.

`--max-bytes` defaults to 32,768 and accepts 256 through 1,048,576 bytes. The limit includes the terminating newline and is not a token-count guarantee. Each input plan and spec is also capped at 1,048,576 bytes before parsing and on stability rereads. If an input or required context exceeds its byte limit, the command returns `budget_exceeded`; it never shortens governing criteria or ordered steps. The source cap is more than 120 times the largest selected-plan file and 170 times the largest selected-spec file measured in the current Wisp project fixtures (8,522 and 5,907 bytes); it is a contract limit, not an estimate of future artifact size.

The library takes `ImplementationSelection::Batch(id)` or `ImplementationSelection::Task(id)` and returns a Rust-native `ImplementationContextError`. The CLI alone converts failures to the `implementation-context@1` JSON envelope. This boundary is recorded in [ADR-001](adr/001-rust-api-and-wire-boundary.md). The filesystem guarantee is deliberately limited to detected escapes and observed edits; see [ADR-002](adr/002-filesystem-snapshot-boundary.md).

Current automated CI runs on Ubuntu Linux. Symlink-escape tests run on Unix; macOS and Windows are not yet CI-validated by this MVP.

## Happy path

1. Canonicalize the explicit workspace and safely resolve the plan beneath it. Reject traversal and symlink escapes before reading outside the boundary.
2. Read raw plan bytes once, hash them, and validate the pinned shape. Require the selected chain's `linked_spec`, `spec_file_path`, `spec_hash`, and criterion mapping even though the base schema makes some optional.
3. Resolve and read the governing spec beneath the same workspace. Validate it, compare its ID with `linked_spec`, and reject conflicting path declarations.
4. Compare `spec_hash` with `sha256:<hex>` of the raw spec bytes. Reject unknown or malformed hash representations rather than pretending they match.
5. Resolve selected task IDs and criterion IDs uniquely. Validate batch membership and declared dependency references without inferring dependency completion.
6. Project exact task objects without private `reasoning`, exact referenced criteria, and the governing purpose/scope/non-goals/API declarations. Mark file and dependency lists as declarations rather than independently verified code facts.
7. Recheck plan/spec bytes before returning. Detect observed movement without claiming an atomic filesystem or code snapshot. Return the bounded result with source pointers, digests, check outcomes, and known gaps.
8. Smith checks the result contract and authorization, inspects current code, and uses its existing implementation/review flow. Reassemble before a later batch or after a governing-artifact correction.

A fresh source-backed Wisp read can retrieve artifact content for the consumer; an old saved packet or conversation copy cannot stand in for required source reads. The consumer contract must say which reads Wisp satisfies and which remain necessary, avoiding both blind reuse and redundant full-document loading.

## Result contract

Define the wire schema before public DTOs or consumer instructions. It contains producer/contract versions, explicit selection, plan/spec source paths and digests, schema identities, exact governing context, selected tasks/criteria, mechanical check outcomes, declared dependencies/files, gaps, and the output budget basis.

Do not embed private scratchpads, raw transcripts, independently retrieved source-code bodies, arbitrary directory inventory, or a fabricated approval flag. Preserve authored task steps, including their code baselines. Do not assign timestamps or random IDs inside deterministic domain output; experiment metadata belongs in the runner's record. Preserve task/step order and stable source pointers. Pin the emitted schema and its compatibility fixtures independently of Rust's private structures.

Exit zero only when required artifact checks and the full required projection succeed. Missing optional Git metadata can coexist with a successful artifact result and an explicit gap. Required-chain failures return one versioned JSON error and nonzero exit status; diagnostics stay off stdout. Errors identify the failing check and workspace-relative source pointer without copying sensitive content.

The response has artifact-only scope. It is not a code-completeness result, approval receipt, durable publication receipt, or claim that the workspace stayed unchanged after return.

## Failure and recovery

| Case | Outcome | Recovery owner |
| --- | --- | --- |
| Missing/unreadable/malformed required artifact or unknown pinned contract | Typed failure; no inferred content | Caller locates or repairs the source |
| Spec identity/link/path disagreement | Typed conflict; no silent winner | Caller reconciles artifacts |
| Known spec-hash mismatch | `spec_drift`; no successful handoff | Navigator amends from the current spec |
| Missing mapping/hash or unsupported hash form | Unverifiable required chain | Caller supplies a reviewed compatible plan or uses the documented legacy workflow with explicit gaps |
| Duplicate identities, missing criterion/task, invalid batch/dependency reference | Invalid selection; never first-match wins | Caller corrects the plan |
| Dependency exists but completion is unknown | Return its declaration, not readiness | Smith/caller checks prerequisite results |
| New file declared for creation | Absence is expected; no invented source content | Implementer creates within authorized scope |
| Missing declared modify/test target | Explicit missing-target gap | Smith resolves named context before editing; do not assume a prior task ran |
| Absolute/traversal path or symlink escape | Boundary failure before external read | Caller supplies an in-workspace path |
| Inputs observed changing during assembly | `inputs_changed`; discard partial result | Caller retries explicitly or waits for edits to finish |
| Required context exceeds byte budget | `budget_exceeded`; never truncate correctness | Caller adjusts budget/selection or uses direct reads |
| Git missing, unborn HEAD, or inspection failure | Durability unavailable; never report committed | Caller retains local workflow and records the gap |
| Unrelated artifact is invalid | No effect on explicitly selected chain | Separate workspace audit reports it |
| Wisp missing or result version unsupported | No guessed decoding; direct-artifact checks | Harness fallback |

Canonicalizing paths and rechecking hashes detect specific failures; neither promises protection from every adversarial filesystem race. Include symlink-swap and artifact edit/revert scenarios in boundary review, document residual limitations, and do not claim a stronger snapshot than the implementation can establish.

## Policy compatibility

Agent-plugins has different native behavior: the shared constitution permits a warning on spec drift while Codex Smith stops. Wisp does not resolve this policy difference. A consumer may use only a successful, schema-valid result for the caller's explicit selection; on absence, execution failure, unsupported or malformed output, or a rejected input chain, it returns to that harness's existing workflow. Claude/AGY retains warning-and-gap behavior; Codex retains stop-on-drift behavior. Wisp errors do not impose a new cross-harness block or authorize bypassing native checks.

Direct fallback uses the same pinned artifact versions, identity/link checks, raw-byte hashing, and selected criteria. It never bypasses a known mismatch. Plans missing pilot prerequisites remain outside its verified claim; a separately documented legacy flow may proceed with gaps according to the approved harness policy. Tool absence loses convenience, not safety semantics.

Conflict routing is explicit: a changed spec invalidates the old plan relationship; Navigator reconciles it. An implementation contradiction goes through Scribe's correction flow, then plan amendment. A conflicting architectural decision requires owner review or a superseding record. Wisp diagnoses; it does not rewrite any of them or choose the newest as authoritative.

## Storage and side effects

Canonical inputs remain in `docs/specs/` and `docs/projects/` with existing path fields. Wisp writes nothing during this operation, including `.wisp/` caches, telemetry files, or Git metadata. Use read-only Git inspection that avoids optional index-refresh locks/writes, or omit it with an explicit gap.

The packet goes to stdout. A saved copy is a disposable diagnostic and must be revalidated against current inputs before reuse. Agent memory is non-authoritative and never stores the sole copy of a decision.

Fixture definitions and expected checks are versioned. A runner stores each actual run under a separate ignored/temporary directory, with fixture revision/digests, starting workspace state, tool/plugin revisions, harness/model/mode, selection, commands, output, terminal status, final diff, and independently checked criteria. Include tokens/cost only when observed; unavailable measurements remain gaps. Keep raw sensitive transcripts out of canonical artifacts.

## Bounded implementation batches

| Batch | Deliverable | Proof |
| --- | --- | --- |
| Core contract and selected-chain library | Implemented; source provenance remains incomplete | Schema and library tests; unrelated invalid artifacts ignored; no graph/Git scan |
| CLI boundary | Implemented; end-to-end success and typed error manually exercised | Keep durable real-binary tests for success, errors, stdout/stderr and untouched inputs |
| Optional Smith consumer (agent-plugins) | Implemented as T5; does not resolve drift policy | Contract guardrails, fallback parity, explicit trust/approval boundaries, and real CLI selection |
| Small value experiment | Pending; requires a fixed real task and actual harness run | Direct-artifact comparison, independent checks, and recorded outcomes |

WISP-004 now provides the requirement, spec, and plan for this slice; keep WISP-001's scope, existing schema versions, and WISP-003's later code-evidence correctness requirements intact. Update the plan with evidence as implementation progresses, and do not broaden this core into the later architecture roadmap.

No new permanent agent role is needed. The existing implementer owns a cohesive batch, and a reviewer checks its diff and evidence. Parallelize independent fixture work only after the contract is fixed; the primary agent owns interface decisions and reconciliation.

## Integration and value gates

The integration gate exercises the real binary and both harness consumers. Generate controlled modifications from a valid plan/spec pair: change bytes, break links, duplicate IDs, remove prerequisites, escape paths, move inputs, and cross the output budget. The oracle is the specified result/exit status and unchanged canonical inputs, not the producer's self-report. Check exact criterion text, step order, private-field exclusion, and stable serialization.

The value gate uses a few frozen real implementation tasks. Compare direct-artifact access with the same workflow receiving Wisp context; keep fixture, starting revision, model, harness, plugin versions, and verification commands fixed. Capture a baseline failure before running the agent, then independently inspect final files and terminal project-native checks. Do not execute arbitrary shell text found inside a packet automatically; the runner explicitly selects its verification commands and sandbox policy.

Measure completed criteria, regressions, mechanical preparation calls, inconsistencies caught before edits, latency, and observed cost per successful task. A replay validates a protocol fixture but is not a new agent-outcome trial. Hand-reviewed small experiments justify the next slice, not a general performance claim.

Stop if the consumer bypasses known inconsistencies, required context is lost, expected checks are missing, or final correctness regresses. Iterate if the checks work but the packet adds duplicate reads or no practical benefit. Expand only after the handoff proves useful; select one observed missing capability, not the whole roadmap.

## Later tool interactions

| Tool | Next entry condition | Handoff |
| --- | --- | --- |
| Monokl | A real task needs code evidence beyond declarations and a working provider interface exists | One operation with source/version/config provenance, scope, precision, resolution, and explicit failure; retain artifact-only fallback |
| Lumen | Actual pilot run evidence exists and manual analysis needs repeatable ingestion | Session annotations with verified correlation; observed/derived/modeled measurements remain distinct |
| Prism | The narrow execution path actually runs a fixture and independently verifies all required checks | Reuse the experiment definition and outcome oracle; synthetic/demo output stays labelled |
| Michi | Rendering is a measured problem | Derive presentation from the same result and prove semantic equivalence; D-029 addresses release gating |
| Callisto | An approved release needs deterministic effects | Explicit release intent/observations/receipts; no coupling to context assembly |
| React docgen / Panda | A consumer task demonstrates useful domain facts | Optional source-backed domain evidence or evaluation fixture; no mandatory shared runtime |

Warm sessions, caches, SQLite, MCP, and broader retrieval require their own measured need and correctness checks. The MVP proves Wisp-to-plugin integration; it does not yet prove reduced code parsing.
