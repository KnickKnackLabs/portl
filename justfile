default: check

check:
    cargo check --workspace --all-features

build:
    cargo build --workspace --all-features

test:
    cargo test --workspace --all-features

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-features --all-targets -- -D warnings

deny:
    cargo deny --all-features check

lint: fmt-check clippy

ci: check lint test
