# Security Policy

## Supported Versions

Only the latest released minor version of `tvek` receives security updates and patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://github.com/Xpt0xZv/tvek/security/advisories/new).

When submitting a report, please include:

1. A description of the vulnerability and its potential impact.
2. Minimal reproduction steps or a proof-of-concept payload (e.g., crafted JSON input, CLI invocation, or LSP frame sequence).
3. Affected operating systems, architectures, and `tvek` version (`tvek --version`).

### Response Timeline

- **Acknowledgement**: Within 48 hours of submission.
- **Triage & Assessment**: Within 5 business days.
- **Remediation & Coordinated Disclosure**: Security fixes are released as soon as verified, accompanied by a GitHub Security Advisory.

## Security Architecture & Invariants

`tvek` is engineered for high-assurance environments and untrusted inputs:

- **Zero Third-Party Crate Dependencies**: Built exclusively with the Rust standard library (`std`) to eliminate supply-chain risk from transitive crates.
- **Strict Resource & Amplification Bounds**:
  - Default maximum input size cap (`100 MiB`, configurable via `--max-size`).
  - Maximum JSON nesting depth of `512`.
  - Bounded streaming duplicate-key sets, sorted DOM memory accounting, and output amplification limits.
  - Bounded directory traversal depth (`64` levels) and discovered file caps (`100,000` files).
- **Safe Atomic File Writes**:
  - Refuses to overwrite symbolic links or read-only files in-place (`--write`).
  - Writes to unpredictable sibling temporary files and cleans up on failure.
- **Diagnostic Terminal Sanitization**:
  - Sanitizes ASCII control characters, Unicode format characters (`Cf`), line/paragraph separators (`Zl`/`Zp`), and bidirectional (`BiDi`) override codepoints in diagnostic snippets to prevent terminal escape injection and Trojan Source spoofing.
- **Hardened LSP Transport**:
  - Enforces strict `Content-Length` bounds, rejects duplicate `Content-Length` headers, and caps JSON-RPC payload depth and node counts.

## Verifying Release Artifacts

All official GitHub release binaries include SHA-256 checksums (`SHA256SUMS`) and cryptographic SLSA build provenance attestations generated on GitHub Actions.

### Verify SLSA Build Provenance

Using the [GitHub CLI (`gh`)](https://cli.github.com/):

```bash
gh attestation verify tvek-<target>.tar.gz --repo Xpt0xZv/tvek
```

### Verify SHA-256 Checksums

```bash
sha256sum -c SHA256SUMS --ignore-missing
```
