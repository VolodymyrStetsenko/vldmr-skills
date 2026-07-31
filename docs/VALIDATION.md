# Validation Record

## Purpose

This document records reference coverage, fixture validation, and external
repository executions for release `1.0.0`. Results characterize implemented
static detections; they do not establish complete vulnerability coverage.

## Environment

| Parameter | Value |
| --- | --- |
| Operating system | Linux |
| Python | 3.14.4 |
| Dependencies | Python standard library only |
| Network access during analysis | None |
| Analysis mode | Static, comment-stripped source enumeration |

## Reference Coverage

### ZK vulnerability classes

| Class | Coverage | Implementation |
| --- | --- | --- |
| Under-constrained circuits | Detected | `under-constrained-witness`, `unconstrained-output` |
| Nondeterministic circuits | Partial | Witness-only assignment enumeration |
| Arithmetic overflow or underflow | Manual analysis | Taxonomy procedure |
| Mismatched bit lengths | Manual analysis | Taxonomy procedure |
| Unused public inputs | Detected | `unused-public-input` |
| Fiat-Shamir transcript weakness | Not detected | Manual cryptographic review required |
| Trusted setup compromise | Not detected | Artifact provenance review required |
| Assigned but unconstrained values | Detected | `<--` target absent from `===` and `<==` constraints |

### OWASP Smart Contract Top 10 (2026)

| Code | Coverage | Implementation |
| --- | --- | --- |
| SC01 Access control | Partial | Permissionless configuration setters; modifier and inline authorization recognition |
| SC02 Business logic | Partial | Invariant derivation procedure |
| SC03 Price oracle manipulation | Partial | Spot-price, deprecated-feed, and staleness detections |
| SC04 Flash-loan attacks | Partial | Callback and balance-derived accounting detections |
| SC05 Input validation | Manual analysis | Bounds and state-machine procedures |
| SC06 Unchecked external calls | Detected | `unchecked-low-level-call` |
| SC07 Arithmetic errors | Manual analysis | Accounting and bounds procedures |
| SC08 Reentrancy | Partial | External-call and guard enumeration |
| SC09 Integer overflow or underflow | Manual analysis | Arithmetic review procedure |
| SC10 Proxy and upgradeability | Partial | Upgrade authorization, initializer, and self-destruction detections |

`Partial` indicates detection of defined source patterns, not full semantic
coverage of the risk category.

## Fixture Validation

| Component | Fixture scope | Expected flags | Observed flags |
| --- | --- | ---: | ---: |
| `zk-circuit-review` | `sample.circom` | 2 | 2 |
| `verifier-bridge-audit` | `Verifier.sol`, `Withdrawer.sol` | 3 | 3 |
| `evm-invariant-scan` | `Vault.sol`, `DefiVault.sol` | 10 | 10 |

The fixture set verifies supported positive detections. It is not a statistical
measure of false-positive or false-negative rates.

## External Repository Executions

| Target | Commit | Component | Files analyzed | Flags |
| --- | --- | --- | ---: | ---: |
| Semaphore | `4dbc39b` | `zk-circuit-review` | 1 | 0 |
| Semaphore | `4dbc39b` | `verifier-bridge-audit` | 14 Solidity source files in selected scope | 0 |
| Semaphore | `4dbc39b` | `evm-invariant-scan` | 14 Solidity source files in selected scope | 1 |
| circomlib | `35e54ea` | `zk-circuit-review` | 57 | 3 |
| World ID contracts | `f959f72` | `verifier-bridge-audit` | 25 | 8 |
| World ID contracts | `f959f72` | `evm-invariant-scan` | 19 | 0 |
| Uniswap v4 core | `46c6834` | `evm-invariant-scan` | 38 | 0 |
| Uniswap v4 core | `46c6834` | `verifier-bridge-audit` | 38 | 0 verifiers, 0 flags |

Generated JSON and markdown artifacts are stored under `examples/`. Absolute
paths in artifacts reflect the validation environment.

## Observations

1. circomlib produced three `unused-public-input` flags. The referenced input
   identifiers occur only at their declarations in the analyzed template files.
   Parent-template composition and deployment relevance require separate review.
2. Semaphore produced one `permissionless-config-setter` flag for
   `updateMember`. Authorization is delegated through inherited implementation;
  the static pattern is retained as an analysis observation.
3. World ID verifier consumers produced replay, binding, and mutable-verifier
   flags. These require system-level review of identity-state transitions,
   verifier governance, and replay semantics before classification.
4. Uniswap v4 served as a negative control for verifier detection and for
   initializer/access-control heuristics.

## Detection Corrections Identified During Validation

- Circuit witness-target extraction now selects the signal adjacent to `<--` in
  single-line loops instead of selecting the loop variable.
- EVM access-control analysis recognizes `initializer`/`reinitializer` modifiers
  and common inline `msg.sender` authorization patterns.
- EVM initializer detection requires proxy or upgradeability context.
- Verifier detection recognizes optimized Yul pairing-precompile patterns.
- Replay detection recognizes conditional-revert and consume-write nullifier
  idioms.

## Limitations

- Imported circuit dependency graphs under excluded vendor directories are not
  traversed.
- Solidity inheritance, modifiers, storage aliases, and inter-contract calls are
  not resolved semantically.
- Public-input ordering, elliptic-curve point validation, subgroup checks,
  transcript construction, and trusted-setup provenance require manual review.
- No claim is made regarding vulnerability absence when no flag is produced.
- External repository results apply only to the recorded commit and selected
  source scope.
