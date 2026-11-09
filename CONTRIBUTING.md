# Contributing to tvek

Thank you for your interest in contributing to **tvek**!

## Core Design Principles

1. **Zero External Dependencies**: `tvek` uses **only** the Rust standard library (`std`). Pull requests that add third-party crates to `[dependencies]` in `Cargo.toml` will not be accepted.
2. **Strict RFC 8259 Compliance**: Any lexer or formatter change must preserve strict compliance with RFC 8259 and pass the full regression suite.
3. **Defense-in-Depth**: All inputs (files, `stdin`, CLI flags, directory trees, and LSP JSON-RPC frames) are treated as untrusted and must respect explicit memory, depth, and size bounds.

## Local Development Workflow

### Prerequisites

- Rust toolchain (`1.79+`, latest `stable` recommended)
- Optional (for Python wheel packaging): Python `3.8+` and [`maturin`](https://www.maturin.rs/) / [`uv`](https://docs.astral.sh/uv/)

### Running Checks Locally

Before opening a pull request, ensure all CI gates pass locally:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Run Clippy with warnings denied across all targets
cargo clippy --locked --all-targets --all-features -- -D warnings

# 3. Run the unit and integration test suite
cargo test --locked --all-targets

# 4. Verify zero external runtime dependencies
cargo tree --locked --edges normal
```

## Security Vulnerabilities

If you discover a security issue, please follow the instructions in [SECURITY.md](SECURITY.md) rather than opening a public issue or pull request.
