# EVM Invariant Scan — contracts

> VLDMR Skills · `evm-invariant-scan` v2.0.0 · 2026-07-31 (UTC)

**Scope:** `/opt/audit-targets/nomad-monorepo/packages/contracts-router/contracts` · 2 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 2 |
| Functions | 8 |
| Entry points (external/public) | 2 |
| Permissionless entry points | 0 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **0** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `Router.sol / enrollRemoteRouter` | external | onlyOwner | yes | no |
| `XAppConnectionClient.sol / setXAppConnectionManager` | external | onlyOwner | no | no |

## Analysis observations

No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source. Derived invariants require implementation and execution in a verification tool.

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 0 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**NO FLAGS.** No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
