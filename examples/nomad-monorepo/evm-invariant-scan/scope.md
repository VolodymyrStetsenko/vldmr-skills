# EVM Invariant Scan — Scope

**Tool:** `evm-invariant-scan` v2.0.0
**Target:** Nomad optics-style cross-chain messaging bridge (blind-target-001)
**Target revision:** `e7246ea1f17ab49e81d39f199bb17153d3f950d2` — *"feat: add token sender to TransferToHook message (#414)"*
**Reviewed:** 2026-07-31 (UTC)
**Assessment basis:** deterministic static enumeration + manual source review of all in-scope Solidity. No compilation, no execution, no network (per security contract).

## Included paths (production Solidity)

| Package | Path | Solidity files | Contracts | Entry pts | Permissionless (scanner) |
| --- | --- | ---: | ---: | ---: | ---: |
| contracts-core | `packages/contracts-core/contracts` | 17 | 19 | 38 | 13 |
| contracts-bridge | `packages/contracts-bridge/contracts` | 7 | 7 | 27 | 16 |
| contracts-router | `packages/contracts-router/contracts` | 2 | 2 | 2 | 0 |
| **Total** | | **26** | **28** | **67** | **29** |

### In-scope contracts

- **core:** `Home`, `Replica`, `NomadBase`, `UpdaterManager`, `XAppConnectionManager`,
  `Version0`, `Merkle`/`MerkleTreeManager` (`Merkle.sol`, `libs/Merkle.sol`),
  `Queue`/`QueueManager` (`Queue.sol`, `libs/Queue.sol`), `libs/Message`, `libs/TypeCasts`,
  `governance/GovernanceRouter`, `governance/GovernanceMessage`,
  `upgrade/UpgradeBeacon`, `upgrade/UpgradeBeaconController`, `upgrade/UpgradeBeaconProxy`,
  interfaces (`IMessageRecipient`, `IUpdaterManager`).
- **bridge:** `BridgeRouter`, `BridgeToken`, `TokenRegistry`, `BridgeMessage`, `Encoding`,
  `ETHHelper`, `vendored/OZERC20`, interfaces (`IBridgeHook`, `IBridgeToken`,
  `ITokenRegistry`, `IWeth`).
- **router:** `Router`, `XAppConnectionClient`.

## Excluded paths (not reviewed — no coverage claimed)

- `**/test/**` — unit tests, harnesses, and mocks:
  `contracts-core/contracts/test/**` (Home.t, NomadBase.t, Replica.t, harnesses/*, utils/*),
  `contracts-bridge/contracts/test/**` (BridgeRouter.t, TokenRegistry.t, BridgeMessage.t,
  harness/*, utils/MockHome, utils/MockWeth, utils/BridgeTest).
- Non-Solidity packages: `deploy/`, `indexer/`, `keymaster/`, `local-environment/`,
  `monitor/`, `multi-provider/`, `sdk*`, `keymaster/`.
- External dependencies resolved by remapping but **not** re-audited here:
  `@openzeppelin/contracts`, `@openzeppelin/contracts-upgradeable`,
  `@summa-tx/memview-sol` (`TypedMemView`). Their internal correctness is assumed;
  only their call sites are reviewed.

## Commands executed

```bash
mkdir -p evm-scan
python3 "$SKILL_DIR/scripts/enumerate_evm.py" packages/contracts-core/contracts   --json evm-scan/enumeration-core.json   --report evm-scan/static-analysis-core.md
python3 "$SKILL_DIR/scripts/enumerate_evm.py" packages/contracts-bridge/contracts --json evm-scan/enumeration-bridge.json --report evm-scan/static-analysis-bridge.md
python3 "$SKILL_DIR/scripts/enumerate_evm.py" packages/contracts-router/contracts --json evm-scan/enumeration-router.json --report evm-scan/static-analysis-router.md
```

Artifacts: `enumeration-{core,bridge,router}.json`, `static-analysis-{core,bridge,router}.md`,
`scope.md`, `review-ledger.md`, `report.md`.

## Scanner flags (inputs to Phase 2 — NOT findings)

| # | Package | Flag | Location | Phase-3 disposition |
| --- | --- | --- | --- | --- |
| F1 | core | `permissionless-config-setter` (`update`) | `Replica.sol:130` | Rejected (updater-signature gated) |
| F2 | bridge | `unchecked-low-level-call` (`_handleTransferToHook`) | `BridgeRouter.sol:378` | Observation (intentional, documented) |
| F3 | bridge | `external-call-no-reentrancy-guard` (`sendTo`) | `ETHHelper.sol:44` | Rejected (trusted targets, no user funds held) |

## Notes

- ZK circuits / proof verifiers: **none present**. Trust is anchored on a bonded
  Updater ECDSA signature and an optimistic timeout, not on a SNARK verifier.
  `verifier-bridge-audit` / `zk-circuit-review` are not applicable.
- The scanner's `permissionless` count flags any function lacking a *recognized*
  modifier; several (e.g. `handle`, `GovernanceRouter.*`) enforce authorization in
  the body or via inherited modifiers and were re-classified during manual review.
