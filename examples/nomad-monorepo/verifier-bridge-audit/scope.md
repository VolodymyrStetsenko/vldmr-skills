# Scope — verifier-bridge-audit

**Target:** Nomad optics-style optimistic bridge
**Repo root:** `/opt/audit-targets/nomad-monorepo`
**Target revision:** `e7246ea1f17ab49e81d39f199bb17153d3f950d2`
(`feat: add token sender to TransferToHook message (#414)`)
**Reviewed (UTC):** 2026-07-31
**Tool:** `verifier-bridge-audit` v2.0.0

## Trust boundary under audit (scope adaptation)

This target has **no ZK / SNARK verifier**. The skill's proof-to-EVM trust
boundary is adapted to the **optimistic Merkle-proof message-verification
boundary**:

- `Replica.prove()` recomputes a Merkle root from an attacker-supplied
  `(leaf, proof, index)` and accepts the leaf iff that root is an *accepted*
  root (`acceptableRoot`). This plays the role of the "verifier".
- `Replica.process()` dispatches a proven message to the recipient handler.
- `BridgeRouter.handle()` is the "consumer": it decodes the message and performs
  the token effect (release from escrow / mint representation).

Mapping to the skill's threat model:
- "public inputs" ⇒ the full formatted message bytes (leaf = `keccak256(message)`).
- "verifying key / verifier trust" ⇒ the *accepted-root set* (`confirmAt`) and
  the bonded Updater signature that admits roots.
- "nullifier / replay state" ⇒ `messages[leaf]` status latch
  (`0 = none`, root value = proven, `LEGACY_STATUS_PROCESSED = 2` = processed).

The ZK-specific lanes (pairing/point encoding, Fiat–Shamir, public-signal
ordering vs a circuit artifact) **do not apply** and are recorded as scope
adaptation, not as passes.

## Included paths

Core (`packages/contracts-core/contracts`):
- `Replica.sol` (proof-consumer / message dispatch — primary)
- `Home.sol` (message origination / root notarization)
- `NomadBase.sol` (updater signature, committedRoot, state)
- `libs/Merkle.sol` (`branchRoot` proof recomputation)
- `libs/Message.sol` (message field parsing)
- `libs/TypeCasts.sol` (address/bytes32 casts)

Bridge (`packages/contracts-bridge/contracts`):
- `BridgeRouter.sol` (`handle` consumer + effects — primary)
- `BridgeMessage.sol` (action/token-id encoding & bounds)

## Context read (outside primary scope, for grounding handler auth)

- `packages/contracts-router/contracts/Router.sol`
  (`onlyRemoteRouter`, `_isRemoteRouter`, `_mustHaveRemote`)
- `packages/contracts-router/contracts/XAppConnectionClient.sol` (`onlyReplica`)
- `packages/contracts-core/contracts/XAppConnectionManager.sol` (`isReplica`)

## Excluded paths

- All `test/`, `harness*/`, `mock*/`, `utils/` under both packages.
- `packages/{deploy,indexer,monitor,sdk*,keymaster,local-environment,multi-provider}`.
- `governance/`, `upgrade/`, `TokenRegistry`, `BridgeToken`, `Encoding`,
  `ETHHelper`, `Queue`, `UpdaterManager` — not on the proof→effect path
  (noted where they bound trust; UpdaterManager slashing not re-derived).
- Vendored OZ / TypedMemView library internals (assumed correct; bounds behavior
  relied upon and stated as an assumption).

## Discovered proof systems

None (optimistic Merkle-proof + ECDSA Updater attestation; no SNARK/STARK).

## Unresolved dependencies

- `@summa-tx/memview-sol/TypedMemView` — `assertType`, `slice`, `index*`
  revert-on-out-of-range behavior is assumed (standard, widely audited).
- `UpdaterManager` bonding/slashing economics not re-derived (optimistic-security
  assumption).

## Commands executed

```bash
git log -1 --format='%H %s'
mkdir -p bridge-audit
python3 "$SKILL_DIR/scripts/scan_verifier.py" packages/contracts-core/contracts \
    --json bridge-audit/scan-core.json --report bridge-audit/static-analysis-core.md
python3 "$SKILL_DIR/scripts/scan_verifier.py" packages/contracts-bridge/contracts \
    --json bridge-audit/scan-bridge.json --report bridge-audit/static-analysis-bridge.md
```

## Scanner result (Phase 1)

Both scans: **0 verifier contracts, 0 consumer call sites, 0 flags.** Expected —
the scanner keys on `verifyProof`/pairing precompiles, which do not exist in an
optimistic Merkle bridge. Zero flags is therefore *not* evidence of safety; the
entire boundary was reviewed manually (Phases 2–4). Artifacts:
`scan-core.json`, `scan-bridge.json`, `static-analysis-core.md`,
`static-analysis-bridge.md`.
