# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the suite follows
[Semantic Versioning](https://semver.org/) per skill.

## [1.1.0] — 2026-07-31

Validation-driven precision upgrade. Each skill was re-tested against the
Semaphore protocol (`4dbc39b`) and its planted fixtures; see
[docs/VALIDATION.md](docs/VALIDATION.md).

### Added

- `zk-circuit-review` 1.1.0 — `unused-public-input` detector (0xPARC class 5:
  inputs optimized out because no constraint references them); reference classes
  for unused public inputs and Fiat–Shamir / "Frozen Heart" transcript checks.
- `evm-invariant-scan` 1.1.0 — OWASP Smart Contract Top 10 (2026) coverage
  extensions: SC03 price-oracle manipulation (`spot-price-oracle`,
  `oracle-deprecated-feed`, `oracle-missing-staleness-check`), SC04 flash-loan
  attacks (`flash-loan-callback`, `balance-based-accounting`), and SC10 proxy /
  upgradeability (`unprotected-upgrade`, `initializer-not-guarded`,
  `selfdestruct-present`).

### Changed

- `verifier-bridge-audit` 1.1.0 — eliminated the false positives / false
  negative observed on Semaphore: verifier detection now recognizes optimized
  Yul verifiers (decimal precompile `8`, `pPairing`/`checkPairing`); replay-guard
  detection recognizes `if (nullifiers[x]) revert` and consume-write idioms;
  proof-to-context binding accepts `scope`/`nullifier`/domain data in the
  public-input arguments, not only `msg.sender`.

## [1.0.0] — 2026-07-31

### Added

- `zk-circuit-review` 1.0.0 — signal/constraint enumeration and soundness review
  for Circom, Noir, and Halo2 circuits, with an under-constrained-output hunt.
- `verifier-bridge-audit` 1.0.0 — on-chain verifier and public-input binding
  audit covering proof replay, input aliasing, verifying-key trust, and
  nullifier handling.
- `evm-invariant-scan` 1.0.0 — EVM entry-point and access-control map plus a
  machine-checkable invariant catalog for fuzzing and formal verification.
- Repository governance: README, contributing guide, security policy, code of
  conduct, and MIT license.
