# EVM Invariant Scan — Review Ledger

Every scanner flag and reasoning candidate appears exactly once with one
disposition (`Finding` / `Observation` / `Rejected`). Evidence levels per
`references/reasoning-workflow.md` (E0 pattern → E3 executable proof).

Reviewer lanes (lead performed all lanes sequentially with separate evidence
tables; no independent subagent runtime available — recorded as a limitation).
Lane key: L1 system/state model · L2 invariant attacker · L3 interaction
attacker · L4 lifecycle/privilege attacker · CH independent challenge pass.

---

## System / state model (L1)

- **Assets/liabilities:** canonical ERC-20 escrowed in `BridgeRouter` (local-origin
  tokens); representation `BridgeToken` supply minted/burned by `BridgeRouter`
  against remote messages. Liability = outstanding representation supply + escrow.
- **Roles:** `Updater` (bonded, signs Home roots), `Owner`/Governance (per-contract
  `onlyOwner`, ultimately the `GovernanceRouter`), `RecoveryManager`, `Watcher`
  (can unenroll a Replica for a fraudulent Home), `Replica` (authenticated message
  sink for `Router.handle`).
- **Trust boundary:** cross-chain message authenticity is enforced ONLY on the
  destination `Replica` via `acceptableRoot(messages[hash])` + optimistic timeout.
  Everything downstream (`BridgeRouter.handle`, `GovernanceRouter.handle`) trusts
  that the `Replica` only calls `handle` for genuinely proven messages.
- **State machines:** `NomadBase.state ∈ {UnInitialized, Active, Failed}`;
  `Replica.messages[hash] ∈ {0=None, calculatedRoot, 1=LEGACY_PROVEN, 2=LEGACY_PROCESSED}`;
  `Replica.confirmAt[root]` (0 = unknown/never-confirmable, else timestamp).
  Governance recovery latch `recoveryActiveAt`.
- **Sentinels / defaults (critical):**
  - `messages[hash]` default `0` == "never proven".
  - `confirmAt[root]` default `0` == "root never seen; not acceptable".
  - `acceptableRoot` MUST return `false` for the zero root, otherwise the default
    `messages[hash]==0` aliases to "proven". Safety therefore depends entirely on
    `confirmAt[bytes32(0)]` remaining `0`.
- **Zero-value aliasing question (per skill discipline):** does any reachable write
  set `confirmAt[0] != 0`? → `Replica.initialize` executes
  `confirmAt[_committedRoot] = 1` with **no** `_committedRoot != 0` guard ⇒ if a
  Replica is initialized with `_committedRoot == 0`, the zero root becomes
  acceptable and every unproven message passes `process`. This is candidate **C-L1-1**.

---

## Candidate ledger

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| **C-L1-1 / C-L2-1** | L1+L2 | `Replica.sol:100-113,182-201,207-224,246-259` | `acceptableRoot(0)` must be false so `messages[hash]==0` (unproven) can never be processed | **E2** | **Finding (High)** | `initialize` sets `confirmAt[_committedRoot]=1` with no zero-check; `process`/`proveAndProcess` read `messages[hash]` default 0 into `acceptableRoot`. Full trace below. |
| C-L4-1 | L4 | `Replica.sol:104-113` | initializer params must not collapse two security states | E2 | Finding (folded into C-L1-1) | Same root cause: missing `_committedRoot != 0` validation. Recorded once under C-L1-1. |
| F1 / C-L2-2 | scanner+L2 | `Replica.sol:130` `update` | only Updater can add a confirmable root | E1 | **Rejected** | `update` requires `_isUpdaterSignature(_oldRoot,_newRoot,sig)` and `_oldRoot==committedRoot`. Not permissionless; the scanner missed the inline signature guard. Cannot set `confirmAt[0]` without an updater sig over newRoot=0. |
| F2 / C-L3-1 | scanner+L3 | `BridgeRouter.sol:378` `_handleTransferToHook` `_hook.call` | unchecked low-level call return | E1 | **Observation** | Intentional & documented: hook "need not exist, need not execute successfully"; tokens are delivered to `_hook` *before* the call (CEI satisfied for accounting). No value is lost by the bridge on hook failure — the hook owns the tokens. Reentrancy blocked (see CH-3). |
| F3 / C-L3-2 | scanner+L3 | `ETHHelper.sol:44` `sendTo` | external call w/o reentrancy guard | E1 | **Rejected** | Calls only immutable trusted `weth.deposit` then `bridge.send`; no attacker-controlled callback, ETHHelper holds no persistent user funds, WETH is minted 1:1 from `msg.value` in the same call. No CEI violation with security impact. |
| C-L3-3 | L3 | `BridgeRouter.sol:_dust` (`send`) | ignored `.send` boolean | E1 | **Observation** | 2300-gas `.send`, return intentionally ignored; failure only skips an optional gas-faucet dust. No accounting effect. |
| C-L4-2 | L4 | `GovernanceRouter.sol:474` `executeCallBatch` (no modifier) | only authenticated governance batches execute | E1 | **Observation** | Permissionless by design but requires `inboundCallBatches[hash]==Pending`, set only by `_handleBatch` reachable exclusively via `handle` (`onlyReplica` + `onlyGovernorRouter`). Anyone may *trigger* an already-authenticated batch; they cannot inject one. Downstream of the Replica trust (amplifies C-L1-1 impact). |
| C-L4-3 | L4 | `BridgeToken.sol:93` `setDetails` (no modifier) | token metadata integrity | E1 | **Rejected** | First call allowed once at deploy (`token.name` empty); thereafter requires supplied name/symbol/decimals to hash to the committed `detailsHash`. Bounded. |
| C-L3-4 | L3 | `BridgeToken.sol:135` `permit` (no modifier) | EIP-2612 signature auth | E1 | **Rejected** | Verifies `ecrecover(...) == _owner` and `_owner != 0` (so a 0-address recover cannot pass), increments nonce. Standard permit. |
| C-L4-4 | L4 | `UpgradeBeaconController.sol:32` `upgrade` / `UpgradeBeacon.sol:fallback` | only controller/owner upgrades implementation | E1 | **Rejected** | `upgrade` is `onlyOwner`; `UpgradeBeacon.fallback` writes implementation only when `msg.sender == controller` (immutable). No unprotected upgrade path. |
| C-L4-5 | L4 | `Home.sol:113`, `Replica.sol:104`, `*Router.initialize` | initializers single-shot | E1 | **Rejected (see note)** | All use OZ `initializer`/`__*_initialize`. Re-initialization blocked. NOTE: this is the same modifier family that, in the historical Nomad incident, still permitted a *fresh* re-init during a beacon upgrade with `committedRoot=0`; the on-chain single-shot latch does not by itself prevent C-L1-1 because C-L1-1 triggers on the *first, legitimate* initialize when the param is zero. |
| C-L3-5 | L3 | `XAppConnectionManager.sol:unenrollReplica` (no modifier) | only permissioned watcher unenrolls | E1 | **Rejected** | Recovers watcher from signature over `(homeDomainHash, domain, updater)` and requires `watcherPermissions[watcher][domain]`. Signature-gated. |
| C-L2-3 | L2 | `Home.sol:206` `update` dequeue loop | `_newRoot` must be a queued root | E1 | **Observation** | `while(true){ if(queue.dequeue()==_newRoot) break; }` reverts (empty queue) if `_newRoot` not present — but `improperUpdate` is checked first and slashes on non-queued roots, so a bad root fails earlier. No fund impact; liveness only. |
| C-L4-6 | L4 | `XAppConnectionManager.sol:ownerEnrollReplica` | replica enrolled to nonzero domain | E0 | **Observation** | No `_domain != 0` check; `isReplica` uses `replicaToDomain[r] != 0`, so a domain-0 enrollment would be invisible to `isReplica`. Owner-only, domain 0 invalid anyway. Hardening only. |

---

## Primary finding — full adversarial trace (C-L1-1), E2

**Property (INV-REPLICA-ROOT):** `acceptableRoot(bytes32(0)) == false` at all times, so an
unproven message (`messages[hash] == 0`) can never satisfy `process`.

**Read-site enumeration for the `messages`/`confirmAt` zero sentinel** (required by the
sentinel challenge protocol):
- `messages[hash]` read in: `proveAndProcess` (L182 `acceptableRoot(messages[_messageHash])`)
  and `process` (L201 `require(acceptableRoot(messages[_messageHash]), "!proven")`).
  Both default to `0` for an unproven leaf → both reach the same security decision.
- `confirmAt[root]` read in: `acceptableRoot` (L253). Written in: `initialize`
  (`confirmAt[_committedRoot] = 1`), `update` (updater-gated), `setConfirmation` (onlyOwner).
- Shortest public path to impact = **direct `process(_message)`** (public, no auth),
  bypassing `prove` entirely.

**Precondition:** a `Replica` is initialized (or, historically, re-initialized during a
beacon upgrade) with `_committedRoot == bytes32(0)`. The contract does not reject this.
Per the skill contract, initializer parameters are treated as adversarially chosen unless
the code enforces validity — here it does not.

**Trace:**
1. `Replica.initialize(remoteDomain, updater, _committedRoot = 0x0, optimisticSeconds)`
   → `committedRoot = 0x0`; `confirmAt[0x0] = 1`.
2. Attacker crafts `_message` with `destination = localDomain`, `recipient =` target
   xApp (e.g. the local `BridgeRouter`), and attacker-chosen `origin`, `sender`, `nonce`,
   `body`. The message was never dispatched anywhere, so `messages[keccak(_message)] == 0`.
3. Attacker calls `Replica.process(_message)` (public):
   - `destination == localDomain` ✔ (attacker set it)
   - `acceptableRoot(messages[hash]) = acceptableRoot(0)`: not `1`, not `2`,
     `confirmAt[0] == 1 != 0`, `block.timestamp >= 1` ⇒ **true** ✔
   - `entered == 1` ✔ → sets `messages[hash] = 2`
   - calls `recipient.handle(origin, nonce, sender, body)` with attacker-controlled args.
4. `recipient = BridgeRouter`: `handle` is `onlyReplica` (msg.sender IS the Replica ✔) and
   `onlyRemoteRouter(origin, sender)` (attacker sets `origin` = an enrolled remote domain
   and `sender` = that domain's enrolled router ✔). Body encodes a `Transfer` action →
   `_handleTransfer` → `_giveTokens` mints representation tokens or releases escrow to the
   attacker's recipient. **Bridge fully drained.**
   - Alternatively `recipient = GovernanceRouter` with `origin/sender` = governor router →
     `_handleBatch` marks an arbitrary `Batch` Pending → `executeCallBatch` → `_callLocal`
     executes attacker calldata (incl. `UpgradeBeaconController.upgrade`) ⇒ **total system
     takeover.**

**Impact:** complete loss of cross-chain message authentication → drain of all bridged
assets and/or governance takeover. This is the exact class and root cause of the August
2022 Nomad incident (~$190M).

**Why High (not unconditionally Critical):** the trigger is an initialization/deployment
parameter (`_committedRoot == 0`), not a value the attacker sets at runtime. Under a
deployment that always initializes with a genuine non-zero committed root, `confirmAt[0]`
stays `0` and the bug is dormant. The severity is therefore **High with Critical impact**
— a missing input-validation invariant whose realization has catastrophic consequences and
which has historically occurred in production for this exact codebase family.

---

## Independent challenge pass (CH) — lead, separate pass

- **CH-1 (C-L1-1):** Tried to find an earlier revert on the `process` path. There is none
  between `destination` check and the `acceptableRoot(0)` check for an attacker-crafted
  message; `entered==1` holds on first call. Tried to prove `acceptableRoot(0)` is false:
  it is false ONLY if `confirmAt[0]==0`, which `initialize` violates for `_committedRoot==0`.
  Tried the alternate consumer `proveAndProcess`: it also short-circuits on
  `acceptableRoot(messages[hash]) || prove(...)` → same true result. Both consumer paths
  confirmed. Challenge does **not** reject; finding stands at E2. Remaining assumption:
  a deployment initializes with a zero committed root — documented as the precondition.
- **CH-2 (F1/update):** Confirmed the updater ECDSA check blocks setting `confirmAt[0]`
  via `update` without the bonded updater's signature over `newRoot=0`. Rejection holds.
- **CH-3 (F2/hook reentrancy):** The arbitrary `_hook.call` runs inside `Replica.process`
  where `entered == 0`, so re-entry into `process`/`proveAndProcess` reverts (`!reentrant`).
  `_hook` is not an enrolled Replica, so it cannot re-enter `BridgeRouter.handle`
  (`onlyReplica`). Public `send`/`sendToHook`/`migrate` only debit the caller. No profitable
  reentrancy. Observation holds.
- **CH-4 (F3/ETHHelper):** Targets are immutable `weth`/`bridge`; no persistent balance to
  drain, WETH minted 1:1 from `msg.value`. Rejection holds.

---

## Coverage / limitations

- No independent subagent runtime: all four lanes + challenge performed sequentially by the
  lead with separate evidence tables. Recorded as a limitation, not a skipped lane.
- Static, source-only review under the security contract: **no compilation, no execution,
  no fuzzing.** The E2 finding rests on explicit source semantics; it is not E3.
  `INV-REPLICA-ROOT` should be fuzzed/PoC'd to reach E3.
- `TypedMemView`, OpenZeppelin, and `MerkleLib` internals assumed correct; only call sites
  reviewed. `libs/Queue`, `Encoding`, `GovernanceMessage`, `BridgeMessage` parsing reviewed
  for authorization-relevant behavior only, not exhaustively for encoding edge cases.
