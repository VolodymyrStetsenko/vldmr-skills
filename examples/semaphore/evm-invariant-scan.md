# EVM Invariant Scan — contracts

> VLDMR Skills · `evm-invariant-scan` v1.2.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/semaphore/packages/contracts/contracts` · 5 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 4 |
| Functions | 32 |
| Entry points (external/public) | 11 |
| Permissionless entry points | 10 |
| Conservation seeds (supply vs. balances) | 0 |
| **Leads** | **1** |

## Leads

Each row is a **lead** to confirm against the code, not a final finding.

| # | Severity | Kind | Function | Location | Note |
| ---: | --- | --- | --- | --- | --- |
| 1 | High | `permissionless-config-setter` | `updateMember` | Semaphore.sol:92 | a setter/admin-style function writes state with no access modifier — anyone can change protocol configuration; confirm intended |

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 10 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Verdict

**Review required.** 1 high-severity lead(s) (upgrade / access-control / reentrancy / oracle). Confirm before deployment.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Leads are structural; a flagged pattern is not proof of a bug, and an absent flag is not proof of safety. Pair with fuzzing and manual review.
