default:
    @just --list

build:
    cargo build --workspace --locked

test:
    cargo test --workspace --locked

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

audit:
    cargo deny check

docs-lint:
    scripts/docs-lint.sh

# Callisto config, package discovery and pending changesets; the same gate as CI's Changesets job
changesets:
    callisto status --check
    callisto release --dry-run --format text

# Record a pending change for the next release, e.g. `just changeset minor "Add the search command"`
changeset package bump summary:
    callisto add --package cargo/{{ package }}:{{ bump }} --summary "{{ summary }}"

ci: docs-lint fmt-check test lint doc audit changesets

pre-commit: fmt-check lint

pre-push: ci
