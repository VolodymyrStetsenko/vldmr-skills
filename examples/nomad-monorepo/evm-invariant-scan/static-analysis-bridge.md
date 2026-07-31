# EVM Invariant Scan — contracts

> VLDMR Skills · `evm-invariant-scan` v2.0.0 · 2026-07-31 (UTC)

**Scope:** `/opt/audit-targets/nomad-monorepo/packages/contracts-bridge/contracts` · 7 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 7 |
| Functions | 93 |
| Entry points (external/public) | 27 |
| Permissionless entry points | 16 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **2** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `BridgeRouter.sol / initialize` | public | initializer | no | no |
| `BridgeRouter.sol / handle` | external | onlyReplica, onlyRemoteRouter, _origin, _sender | no | no |
| `BridgeRouter.sol / send` | external | none detected | no | no |
| `BridgeRouter.sol / sendToHook` | external | none detected | no | no |
| `BridgeRouter.sol / enrollCustom` | external | onlyOwner | no | no |
| `BridgeRouter.sol / migrate` | external | none detected | no | no |
| `BridgeRouter.sol / renounceOwnership` | public | onlyOwner | no | no |
| `BridgeToken.sol / initialize` | public | initializer | no | no |
| `BridgeToken.sol / burn` | external | onlyOwner | no | no |
| `BridgeToken.sol / mint` | external | onlyOwner | no | no |
| `BridgeToken.sol / setDetailsHash` | external | onlyOwner | yes | no |
| `BridgeToken.sol / setDetails` | external | none detected | no | no |
| `BridgeToken.sol / permit` | external | none detected | yes | no |
| `BridgeToken.sol / transferOwnership` | public | IBridgeToken, OwnableUpgradeable, onlyOwner | no | no |
| `BridgeToken.sol / renounceOwnership` | public | onlyOwner | no | no |
| `ETHHelper.sol / sendTo` | public | none detected | no | yes |
| `ETHHelper.sol / send` | external | none detected | no | no |
| `ETHHelper.sol / sendToEVMLike` | external | none detected | no | no |
| `TokenRegistry.sol / initialize` | public | initializer | yes | no |
| `TokenRegistry.sol / ensureLocalToken` | external | onlyOwner, address, _local | no | no |
| `TokenRegistry.sol / enrollCustom` | external | onlyOwner | no | no |
| `TokenRegistry.sol / renounceOwnership` | public | onlyOwner | no | no |
| `OZERC20.sol / transfer` | public | bool | no | no |
| `OZERC20.sol / approve` | public | bool | no | no |
| `OZERC20.sol / transferFrom` | public | bool | no | no |
| `OZERC20.sol / increaseAllowance` | public | bool | no | no |
| `OZERC20.sol / decreaseAllowance` | public | bool | no | no |

## Analysis observations

The following static-analysis observations require source-level and state-transition verification before classification as findings.

| # | Severity | Kind | Function | Location | Note |
| ---: | --- | --- | --- | --- | --- |
| 1 | Medium | `unchecked-low-level-call` | `_handleTransferToHook` | BridgeRouter.sol:378 | low-level .call/.delegatecall return value may be unchecked — confirm the success boolean is handled |
| 2 | High | `external-call-no-reentrancy-guard` | `sendTo` | ETHHelper.sol:44 | permissionless function makes an external call without a nonReentrant guard — verify checks-effects-interactions ordering |

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 16 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**REVIEW REQUIRED.** 1 observation(s) are mapped to high-impact EVM risk classes and require manual verification.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
