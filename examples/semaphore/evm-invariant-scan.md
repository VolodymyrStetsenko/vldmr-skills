# EVM Invariant Scan — contracts

> VLDMR Skills · `evm-invariant-scan` v1.0.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/semaphore/packages/contracts/contracts` · 5 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 4 |
| Functions | 32 |
| Entry points (external/public) | 11 |
| Permissionless entry points | 10 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **1** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `Semaphore.sol / createGroup` | external | uint256, groupId | no | no |
| `Semaphore.sol / createGroup` | external | uint256, groupId | no | no |
| `Semaphore.sol / createGroup` | external | uint256, groupId | no | no |
| `Semaphore.sol / updateGroupAdmin` | external | none detected | no | no |
| `Semaphore.sol / acceptGroupAdmin` | external | none detected | no | no |
| `Semaphore.sol / updateGroupMerkleTreeDuration` | external | onlyGroupAdmin, groupId | no | no |
| `Semaphore.sol / addMember` | external | none detected | yes | no |
| `Semaphore.sol / addMembers` | external | none detected | yes | no |
| `Semaphore.sol / updateMember` | external | none detected | yes | no |
| `Semaphore.sol / removeMember` | external | none detected | yes | no |
| `Semaphore.sol / validateProof` | external | none detected | yes | no |

## Analysis observations

The following static-analysis observations require source-level and state-transition verification before classification as findings.

| # | Severity | Kind | Function | Location | Note |
| ---: | --- | --- | --- | --- | --- |
| 1 | High | `permissionless-config-setter` | `updateMember` | Semaphore.sol:92 | a configuration function writes state without a recognized access modifier or inline authorization check |

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 10 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**REVIEW REQUIRED.** 1 observation(s) are mapped to high-impact EVM risk classes and require manual verification.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
