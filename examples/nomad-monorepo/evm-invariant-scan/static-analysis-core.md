# EVM Invariant Scan — contracts

> VLDMR Skills · `evm-invariant-scan` v2.0.0 · 2026-07-31 (UTC)

**Scope:** `/opt/audit-targets/nomad-monorepo/packages/contracts-core/contracts` · 17 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 19 |
| Functions | 130 |
| Entry points (external/public) | 38 |
| Permissionless entry points | 13 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **1** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `Home.sol / initialize` | public | initializer | no | no |
| `Home.sol / setUpdater` | external | onlyUpdaterManager | no | no |
| `Home.sol / setUpdaterManager` | external | onlyOwner | no | no |
| `Home.sol / dispatch` | external | notFailed | yes | no |
| `Home.sol / update` | external | notFailed | no | no |
| `Home.sol / doubleUpdate` | external | notFailed | no | no |
| `Home.sol / improperUpdate` | public | notFailed, bool | no | no |
| `NomadBase.sol / renounceOwnership` | public | onlyOwner | no | no |
| `Replica.sol / initialize` | public | initializer | yes | no |
| `Replica.sol / update` | external | none detected | yes | no |
| `Replica.sol / proveAndProcess` | external | none detected | no | no |
| `Replica.sol / process` | public | bool, _success | yes | no |
| `Replica.sol / setOptimisticTimeout` | external | onlyOwner | no | no |
| `Replica.sol / setUpdater` | external | onlyOwner | no | no |
| `Replica.sol / setConfirmation` | external | onlyOwner | yes | no |
| `Replica.sol / prove` | public | bool | yes | no |
| `UpdaterManager.sol / setHome` | external | onlyOwner | yes | no |
| `UpdaterManager.sol / setUpdater` | external | onlyOwner | yes | no |
| `UpdaterManager.sol / slashUpdater` | external | onlyHome | no | no |
| `UpdaterManager.sol / renounceOwnership` | public | onlyOwner | no | no |
| `XAppConnectionManager.sol / unenrollReplica` | external | none detected | no | no |
| `XAppConnectionManager.sol / setHome` | external | onlyOwner | no | no |
| `XAppConnectionManager.sol / ownerEnrollReplica` | external | onlyOwner | yes | no |
| `XAppConnectionManager.sol / ownerUnenrollReplica` | external | onlyOwner | no | no |
| `XAppConnectionManager.sol / setWatcherPermission` | external | onlyOwner | no | no |
| `XAppConnectionManager.sol / renounceOwnership` | public | onlyOwner | no | no |
| `GovernanceRouter.sol / initialize` | public | initializer | yes | no |
| `GovernanceRouter.sol / handle` | external | onlyReplica, onlyGovernorRouter, _origin, _sender | no | no |
| `GovernanceRouter.sol / executeGovernanceActions` | external | onlyGovernorOrRecoveryManager | no | no |
| `GovernanceRouter.sol / transferGovernor` | external | onlyGovernor, onlyNotInRecovery | no | no |
| `GovernanceRouter.sol / transferRecoveryManager` | external | onlyRecoveryManager | yes | no |
| `GovernanceRouter.sol / setRouterGlobal` | external | onlyGovernor, onlyNotInRecovery | no | no |
| `GovernanceRouter.sol / setRouterLocal` | external | onlyGovernorOrRecoveryManager | no | no |
| `GovernanceRouter.sol / setXAppConnectionManager` | public | onlyGovernorOrRecoveryManager | no | no |
| `GovernanceRouter.sol / initiateRecoveryTimelock` | external | onlyNotInRecovery, onlyRecoveryManager | yes | no |
| `GovernanceRouter.sol / exitRecovery` | external | onlyRecoveryManager | yes | no |
| `GovernanceRouter.sol / executeCallBatch` | external | none detected | yes | no |
| `UpgradeBeaconController.sol / upgrade` | external | onlyOwner | no | yes |

## Analysis observations

The following static-analysis observations require source-level and state-transition verification before classification as findings.

| # | Severity | Kind | Function | Location | Note |
| ---: | --- | --- | --- | --- | --- |
| 1 | High | `permissionless-config-setter` | `update` | Replica.sol:130 | a configuration function writes state without a recognized access modifier or inline authorization check |

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 13 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**REVIEW REQUIRED.** 1 observation(s) are mapped to high-impact EVM risk classes and require manual verification.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
