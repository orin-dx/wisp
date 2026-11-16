# Contributing to Wisp

Contributions are welcome. This guide covers the development environment, the invariants every change must keep, and the pull request workflow. By participating you agree to the [Code of Conduct](./CODE_OF_CONDUCT.md). Found a security issue? See [SECURITY.md](./SECURITY.md) instead of opening a public issue.

---

## 1. Development environment

### Prerequisites

- **Tools**: install `just`, `rg`, and `cargo-deny`. `rust-toolchain.toml` pins Rust 1.96 (edition 2024); `.prototools` pins the same versions for proto.

### Build and test

Use the repository's `justfile` for the same checks as CI. `just --list` shows the available commands.

```bash
just docs-lint  # Markdown house style, fences, decision references, stale names
just fmt-check
just test
just lint
just doc
just audit      # cargo-deny
```

For one crate use `cargo test -p <crate>` or `cargo clippy -p <crate>` directly.

### Before opening a PR

Run `just ci` before opening a PR. It checks Markdown house style, formatting, locked workspace tests, strict Clippy, rustdoc warnings, and dependency policy.

The [implementation handoff MVP](./docs/08-implementation-handoff-mvp.md) describes the implemented artifact-only handoff and its remaining value gate; it does not change the broader M3 briefing contract.

---

## 2. Engineering invariants

1. **Safe Rust only.** `unsafe_code = "forbid"`, `unwrap_used`/`expect_used` deny — workspace lints, every crate, no exceptions in library code.
2. **Atomic writes only.** Every canonical artifact write is a same-directory tempfile plus rename. Never write a canonical target in place.
3. **The cache is never the authority.** Nothing under `.wisp/` may be the only copy of a fact. See [`PRINCIPLES.md`](./PRINCIPLES.md).
4. **Implement only what the current gated plan's `covers_criteria` requires.** A spec's `non_goals` are binding. If a task needs scope the spec excludes, stop and raise it.
5. **Spec and plan both gate before implementation.** Use `scribe:gate-spec` for the spec, `navigator:plan` to challenge the plan, and `sentinel:gate` for an independent plan verdict. Keep the `verdict@3` evidence; an unrecorded pass is unverified.
6. **Permissive core stays permissive.** `wisp-contracts` and `wisp-model` are `MIT` and must not depend on any `FSL-1.1-MIT` crate, Tokio, MCP types, Monokl types, SQLite, or CLI formatting.
7. **Docs are unwrapped and unpadded.** One paragraph per line, no emoji, no filler. `just docs-lint` enforces the mechanical part.

The full list, with the reasons, is in [`AGENTS.md`](./AGENTS.md). Accepted architectural decisions are indexed in [`docs/adr`](./docs/adr/README.md).

---

## 3. Pull request workflow

1. **Branch** with a descriptive name: `feat/…`, `fix/…`, `docs/…`, `chore/…`.
2. **Tests prove criteria.** Every task's tests name the acceptance criteria they cover; mutation testing (`cargo-mutants`) checks the tests would catch real faults.
3. **Verify locally** with `just ci` and report any check that could not run.
4. **Conventional commits**: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. The message explains why; the diff already shows what.
5. **Cross-repo dependencies** on Monokl and Michi are `git` + `rev` in committed manifests. A local `[patch]` for path development lives in gitignored `.cargo/config.toml` and never in a commit — see [`docs/07-build-and-release.md`](./docs/07-build-and-release.md).
