# EVM Invariant Scan — src

> VLDMR Skills · `evm-invariant-scan` v1.0.0 · 2026-07-31 (UTC)

**Scope:** `/opt/audit-targets/world-id-contracts/src` · 19 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 19 |
| Functions | 146 |
| Entry points (external/public) | 17 |
| Permissionless entry points | 3 |
| Conservation seeds (supply vs. balances) | 0 |
| **Flags** | **0** |

## Entry-point and access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `WorldIDIdentityManagerImplV1.sol / initialize` | public | reinitializer | yes | no |
| `WorldIDIdentityManagerImplV1.sol / registerIdentities` | public | onlyProxy, onlyInitialized, onlyIdentityOperator | yes | no |
| `WorldIDIdentityManagerImplV1.sol / setRegisterIdentitiesVerifierLookupTable` | public | onlyProxy, onlyInitialized, onlyOwner | no | no |
| `WorldIDIdentityManagerImplV1.sol / setSemaphoreVerifier` | public | onlyProxy, onlyInitialized, onlyOwner | no | no |
| `WorldIDIdentityManagerImplV1.sol / setRootHistoryExpiry` | public | onlyProxy, onlyInitialized, onlyOwner | yes | no |
| `WorldIDIdentityManagerImplV1.sol / setIdentityOperator` | public | onlyProxy, onlyInitialized, onlyOwner, address | yes | no |
| `WorldIDIdentityManagerImplV2.sol / initializeV2` | public | reinitializer | no | no |
| `WorldIDIdentityManagerImplV2.sol / deleteIdentities` | public | onlyProxy, onlyInitialized, onlyIdentityOperator | yes | no |
| `WorldIDIdentityManagerImplV2.sol / setDeleteIdentitiesVerifierLookupTable` | public | onlyProxy, onlyInitialized, onlyOwner | no | no |
| `WorldIDRouterImplV1.sol / initialize` | public | reinitializer | yes | no |
| `WorldIDRouterImplV1.sol / addGroup` | public | onlyProxy, onlyInitialized, onlyOwner | no | no |
| `WorldIDRouterImplV1.sol / updateGroup` | public | onlyProxy, onlyInitialized, onlyOwner, IWorldID, oldTarget | no | no |
| `WorldIDRouterImplV1.sol / disableGroup` | public | onlyProxy, onlyInitialized, onlyOwner, IWorldID, oldTarget | no | no |
| `WorldIDRouterImplV1.sol / verifyProof` | external | onlyProxy, onlyInitialized | no | no |
| `VerifierLookupTable.sol / addVerifier` | public | onlyOwner | no | no |
| `VerifierLookupTable.sol / updateVerifier` | public | onlyOwner, ITreeVerifier, oldVerifier | yes | no |
| `VerifierLookupTable.sol / disableVerifier` | public | onlyOwner, ITreeVerifier, oldVerifier | no | no |

## Analysis observations

No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source. Derived invariants require implementation and execution in a verification tool.

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 3 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Analysis status

**NO FLAGS.** No implemented access-control, external-call, oracle, flash-loan, or upgradeability detection pattern matched the analyzed source.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Flags identify structural source patterns. Classification requires manual review and, where applicable, executable verification.
