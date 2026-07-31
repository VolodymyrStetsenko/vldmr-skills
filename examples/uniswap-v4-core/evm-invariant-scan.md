# EVM Invariant Scan — src

> VLDMR Skills · `evm-invariant-scan` v1.0.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/v4-core/src` · 38 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 36 |
| Functions | 181 |
| Entry points (external/public) | 20 |
| Permissionless entry points | 10 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **0** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `ERC6909.sol / transfer` | public | bool | no | no |
| `ERC6909.sol / transferFrom` | public | bool | no | no |
| `ERC6909.sol / approve` | public | bool | no | no |
| `ERC6909.sol / setOperator` | public | bool | no | no |
| `PoolManager.sol / unlock` | external | bytes, result | no | no |
| `PoolManager.sol / initialize` | external | noDelegateCall, int24, tick | no | no |
| `PoolManager.sol / modifyLiquidity` | external | onlyWhenUnlocked, noDelegateCall, BalanceDelta, callerDelta, BalanceDelta, feesAccrued | no | no |
| `PoolManager.sol / swap` | external | onlyWhenUnlocked, noDelegateCall, BalanceDelta, swapDelta | no | no |
| `PoolManager.sol / donate` | external | onlyWhenUnlocked, noDelegateCall, BalanceDelta, delta | no | no |
| `PoolManager.sol / sync` | external | none detected | no | no |
| `PoolManager.sol / take` | external | onlyWhenUnlocked | no | yes |
| `PoolManager.sol / settle` | external | onlyWhenUnlocked, uint256 | no | no |
| `PoolManager.sol / settleFor` | external | onlyWhenUnlocked, uint256 | no | no |
| `PoolManager.sol / clear` | external | onlyWhenUnlocked | no | no |
| `PoolManager.sol / mint` | external | onlyWhenUnlocked | no | no |
| `PoolManager.sol / burn` | external | onlyWhenUnlocked | no | no |
| `PoolManager.sol / updateDynamicLPFee` | external | none detected | no | no |
| `ProtocolFees.sol / setProtocolFeeController` | external | onlyOwner | yes | no |
| `ProtocolFees.sol / setProtocolFee` | external | none detected | no | no |
| `ProtocolFees.sol / collectProtocolFees` | external | uint256, amountCollected | no | yes |

## Analysis observations

No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source. Derived invariants require implementation and execution in a verification tool.

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 10 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**NO FLAGS.** No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
