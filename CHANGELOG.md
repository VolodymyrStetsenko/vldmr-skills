# Changelog

This document records externally observable changes. The project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-31

Initial public release.

### Agentic skill security hardening

- Added an explicit least-privilege and provenance `skill-manifest.json` for
  every component without changing component version `1.0.0`.
- Added complete per-file and aggregate SHA-256 payload integrity validation,
  strict metadata allowlists, external-reference inventory, Unicode/control
  smuggling checks, and unsafe binary/archive detection.
- Added target-content instruction isolation rules to every `SKILL.md`.
- Added deterministic JSON and hash-bound SARIF 2.1.0 security evidence.
- Added a pre-mutation receipt and explicit apply gate for integrity refreshes.
- Added adversarial AST01-AST10 regression coverage and CI enforcement.
- Fixed optional skill selection under Python 3.9 without weakening invalid-name validation.

### Components

- `zk-circuit-review`: deterministic enumeration of Circom, Noir, and Halo2
  source; signal and constraint inventory; witness-only assignment detection;
  unused public-input detection; under-constraint analysis procedure.
- `verifier-bridge-audit`: Solidity verifier and consumer discovery; replay and
  nullifier checks; public-input context-binding analysis; mutable-verifier and
  verifying-key trust analysis.
- `evm-invariant-scan`: Solidity entry-point and access-control enumeration;
  external-call and low-level-call analysis; oracle, flash-loan, accounting,
  upgradeability, initializer, and self-destruction detections; invariant seed
  generation.

### Interfaces

- JSON output to standard output or a path supplied with `--json`.
- Markdown summary generation through `--report`.
- Operational and banner output on standard error.
- Banner suppression through `--no-banner`.

### Validation

- Component fixtures for positive and negative detection behavior.
- Reference executions against Semaphore, circomlib, World ID contracts, and
  Uniswap v4 core at the commits recorded in `examples/README.md`.
