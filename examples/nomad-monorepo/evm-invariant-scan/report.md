# EVM Invariant Scan — Nomad optics-style bridge (blind-target-001)

**Status:** Findings identified

> **Evidence classification:** Scanner flags are source-pattern matches, not
> confirmed vulnerabilities. Promote a flag to a finding only after tracing the
> reachable state transition and demonstrating a violated security property.

**Target revision:** `e7246ea1f17ab49e81d39f199bb17153d3f950d2`
**Scope:** `packages/contracts-core/contracts`, `packages/contracts-bridge/contracts`, `packages/contracts-router/contracts` (test/mocks/harnesses excluded)
**Tool:** `evm-invariant-scan` v2.0.0
**Assessment basis:** static enumeration + manual source review (no compile, no execution, no network — per security contract)
**Contracts:** 28   **Entry points:** 67   **Permissionless (scanner-counted):** 29
**Reviewed:** 2026-07-31

---

## 1. Threat and state model

| Item | Security role | Trust / attacker control | Source evidence |
| --- | --- | --- | --- |
| Bonded `Updater` ECDSA key | notarizes Home roots; sole root authority | trusted; slashing is a stub (`FakeSlashed`) | `NomadBase.sol:120-136`, `UpdaterManager.sol:88-96` |
| `Replica.confirmAt[root]` | maps root → confirmable timestamp; `0` = not acceptable | set by init/updater/governance | `Replica.sol:42-44,253-258` |
| `Replica.messages[hash]` | proof status; default `0` = unproven | derived from proofs; consumed by `process` | `Replica.sol:45,201,246-259` |
| **Zero root `bytes32(0)`** | **must never be acceptable** — it aliases the unproven default | attacker exploits if `confirmAt[0]!=0` | `Replica.sol:100-113,246-259` |
| Escrowed canonical ERC-20 + representation supply | bridge assets/liabilities | attacker target | `BridgeRouter.sol:_takeTokens/_giveTokens` |
| `Owner`/Governance (`GovernanceRouter`) | privileged config, upgrades | trusted | `governance/GovernanceRouter.sol` |
| `RecoveryManager` | can enter/exit recovery, run local calls | trusted | `GovernanceRouter.sol:executeGovernanceActions/recovery` |
| `Watcher` | unenroll Replica of a fraudulent Home | semi-trusted, permissioned by owner | `XAppConnectionManager.sol:unenrollReplica` |
| `UpgradeBeacon` implementation | logic for all proxies | controller/owner-gated | `upgrade/UpgradeBeacon*.sol` |

**Critical state machines & assumptions.**
Cross-chain authenticity is enforced at exactly one place: the destination `Replica`,
via `require(acceptableRoot(messages[hash]))`. All downstream consumers
(`BridgeRouter.handle`, `GovernanceRouter.handle`) are `onlyReplica` and trust that the
Replica only invokes `handle` for genuinely proven messages. The security of the entire
system therefore reduces to the invariant **`acceptableRoot(bytes32(0)) == false`**,
because `messages[hash]` for any never-proven message defaults to `bytes32(0)`. That
invariant holds only while `confirmAt[bytes32(0)] == 0`.

**Security meaning of zero/default values.** `messages[hash]==0` ("unproven") and
`confirmAt[root]==0` ("root unknown / not acceptable") are the two protective sentinels.
`Replica.initialize` writes `confirmAt[_committedRoot] = 1` with no check that
`_committedRoot != 0`; a zero committed root collapses the "unproven" and "acceptable"
states into one. This is Finding 5.1.

**ZK note.** No zero-knowledge circuits or SNARK verifiers exist in scope; trust is an
optimistic updater-signature model. `verifier-bridge-audit` / `zk-circuit-review` are
not applicable.

---

## 2. Entry-point & access map

State-changing public/external entry points. `none detected` = no *recognized* modifier;
authorization may still occur in the body or inherited code (verified in review).

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | :---: | :---: |
| `Home.sol / initialize` | public | `initializer` | yes | no |
| `Home.sol / setUpdater` | external | `onlyUpdaterManager` | yes | no |
| `Home.sol / setUpdaterManager` | external | `onlyOwner` | yes | no |
| `Home.sol / dispatch` | external | `notFailed` | yes | no |
| `Home.sol / update` | external | `notFailed` + inline updater/queue check | yes | yes (slash) |
| `Home.sol / doubleUpdate` | external | `notFailed` + 2 sig checks | yes | yes (slash) |
| `Home.sol / improperUpdate` | public | `notFailed` + updater sig | yes | yes (slash) |
| `Replica.sol / initialize` | public | `initializer` | yes | no |
| **`Replica.sol / update`** | external | inline updater signature (not a modifier) | yes | no |
| **`Replica.sol / proveAndProcess`** | external | none (message-auth only) | yes | yes (recipient) |
| **`Replica.sol / process`** | public | none (message-auth only) | yes | yes (recipient) |
| **`Replica.sol / prove`** | public | none (merkle proof) | yes | no |
| `Replica.sol / setOptimisticTimeout` | external | `onlyOwner` | yes | no |
| `Replica.sol / setUpdater` | external | `onlyOwner` | yes | no |
| `Replica.sol / setConfirmation` | external | `onlyOwner` | yes | no |
| `UpdaterManager.sol / setHome` | external | `onlyOwner` | yes | no |
| `UpdaterManager.sol / setUpdater` | external | `onlyOwner` | yes | yes (Home) |
| `UpdaterManager.sol / slashUpdater` | external | `onlyHome` | no | no |
| `XAppConnectionManager.sol / unenrollReplica` | external | watcher signature (inline) | yes | no |
| `XAppConnectionManager.sol / setHome` | external | `onlyOwner` | yes | no |
| `XAppConnectionManager.sol / ownerEnrollReplica` | external | `onlyOwner` | yes | no |
| `XAppConnectionManager.sol / ownerUnenrollReplica` | external | `onlyOwner` | yes | no |
| `XAppConnectionManager.sol / setWatcherPermission` | external | `onlyOwner` | yes | no |
| `GovernanceRouter.sol / initialize` | public | `initializer` | yes | no |
| `GovernanceRouter.sol / handle` | external | `onlyReplica`, `onlyGovernorRouter` | yes | no |
| `GovernanceRouter.sol / executeGovernanceActions` | external | `onlyGovernorOrRecoveryManager` | yes | yes |
| `GovernanceRouter.sol / transferGovernor` | external | `onlyGovernor`, `onlyNotInRecovery` | yes | yes |
| `GovernanceRouter.sol / transferRecoveryManager` | external | `onlyRecoveryManager` | yes | no |
| `GovernanceRouter.sol / setRouterGlobal` | external | `onlyGovernor`, `onlyNotInRecovery` | yes | yes |
| `GovernanceRouter.sol / setRouterLocal` | external | `onlyGovernorOrRecoveryManager` | yes | no |
| `GovernanceRouter.sol / setXAppConnectionManager` | public | `onlyGovernorOrRecoveryManager` | yes | no |
| `GovernanceRouter.sol / initiateRecoveryTimelock` | external | `onlyRecoveryManager`, `onlyNotInRecovery` | yes | no |
| `GovernanceRouter.sol / exitRecovery` | external | `onlyRecoveryManager` | yes | no |
| `GovernanceRouter.sol / executeCallBatch` | external | none (requires Pending batch) | yes | yes (local calls) |
| `UpgradeBeaconController.sol / upgrade` | external | `onlyOwner` | no | yes (beacon) |
| `UpgradeBeacon.sol / fallback` | fallback | `msg.sender == controller` (inline) | yes | no |
| `Router.sol / enrollRemoteRouter` | external | `onlyOwner` | yes | no |
| `XAppConnectionClient.sol / setXAppConnectionManager` | external | `onlyOwner` | yes | no |
| `BridgeRouter.sol / initialize` | public | `initializer` | yes | no |
| `BridgeRouter.sol / handle` | external | `onlyReplica`, `onlyRemoteRouter` | yes | yes |
| `BridgeRouter.sol / send` | external | none (debits caller) | yes | yes (dispatch) |
| `BridgeRouter.sol / sendToHook` | external | none (debits caller) | yes | yes (dispatch) |
| `BridgeRouter.sol / enrollCustom` | external | `onlyOwner` | yes | yes (mint/burn) |
| `BridgeRouter.sol / migrate` | external | none (self-scoped) | yes | yes (mint/burn) |
| `TokenRegistry.sol / initialize` | public | `initializer` | yes | no |
| `TokenRegistry.sol / ensureLocalToken` | external | `onlyOwner` | yes | yes (deploy) |
| `TokenRegistry.sol / enrollCustom` | external | `onlyOwner` | yes | no |
| `BridgeToken.sol / initialize` | public | `initializer` | yes | no |
| `BridgeToken.sol / mint` | external | `onlyOwner` | yes | no |
| `BridgeToken.sol / burn` | external | `onlyOwner` | yes | no |
| `BridgeToken.sol / setDetailsHash` | external | `onlyOwner` | yes | no |
| `BridgeToken.sol / setDetails` | external | committed-details check (inline) | yes | no |
| `BridgeToken.sol / permit` | external | EIP-2612 signature (inline) | yes | no |
| `BridgeToken.sol / transfer/approve/transferFrom/inc/decAllowance` | public | ERC-20 auth | yes | no |
| `ETHHelper.sol / sendTo` | public | none (debits `msg.value`) | no | yes (weth/bridge) |
| `ETHHelper.sol / send` / `sendToEVMLike` | external | none | no | yes |

---

## 3. Review-lane coverage

| Lane | Reviewer | Scope completed | Candidates | Limitations |
| --- | --- | --- | --- | --- |
| System/state model | lead (sequential) | yes | 1 | none |
| Invariant attacker | lead (sequential) | yes | 3 | no fuzzing (static only) |
| Interaction attacker | lead (sequential) | yes | 5 | dynamic reentrancy not executed |
| Lifecycle/privilege attacker | lead (sequential) | yes | 6 | deployment params treated adversarially |
| Independent challenge | lead (separate pass) | yes | 4 challenges | no independent subagent runtime |

---

## 4. Candidate accounting

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| C-L1-1 (≡C-L2-1,C-L4-1) | lane | `Replica.sol:104-113,182-259` | `acceptableRoot(0)==false` | E2 | **Finding (High)** | `initialize` sets `confirmAt[_committedRoot]=1` unguarded; `process` reads default-0 `messages[hash]` into `acceptableRoot`. |
| F1 / C-L2-2 | scanner+lane | `Replica.sol:130` `update` | only updater adds confirmable root | E1 | Rejected | inline `_isUpdaterSignature` + `_oldRoot==committedRoot`. |
| F2 / C-L3-1 | scanner+lane | `BridgeRouter.sol:378` | unchecked hook `.call` | E1 | Observation | intentional/documented; CEI-safe accounting; reentrancy blocked. |
| F3 / C-L3-2 | scanner+lane | `ETHHelper.sol:44` `sendTo` | ext call w/o guard | E1 | Rejected | trusted immutable targets, no persistent funds. |
| C-L3-3 | lane | `BridgeRouter.sol` `_dust` | ignored `.send` bool | E1 | Observation | optional gas faucet; no accounting effect. |
| C-L4-2 | lane | `GovernanceRouter.sol:474` `executeCallBatch` | only authenticated batch executes | E1 | Observation | requires `Pending` set only via `onlyReplica`+`onlyGovernorRouter` handle. |
| C-L4-3 | lane | `BridgeToken.sol:93` `setDetails` | metadata integrity | E1 | Rejected | committed-details hash check after first deploy. |
| C-L3-4 | lane | `BridgeToken.sol:135` `permit` | signature auth | E1 | Rejected | `ecrecover==owner`, `owner!=0`, nonce increment. |
| C-L4-4 | lane | `UpgradeBeaconController.sol:32`, `UpgradeBeacon.sol` | only owner/controller upgrades | E1 | Rejected | `onlyOwner`; beacon gated on immutable controller. |
| C-L4-5 | lane | `*.initialize` | single-shot init | E1 | Rejected | OZ `initializer`; but does not by itself block C-L1-1 (triggers on first init). |
| C-L3-5 | lane | `XAppConnectionManager.sol:unenrollReplica` | watcher-only unenroll | E1 | Rejected | watcher signature + `watcherPermissions`. |
| C-L2-3 | lane | `Home.sol:206` `update` dequeue | `_newRoot` queued | E1 | Observation | `improperUpdate` slashes non-queued roots first; liveness only. |
| C-L4-6 | lane | `XAppConnectionManager.sol:ownerEnrollReplica` | replica domain nonzero | E0 | Observation | no `_domain!=0`; owner-only; hardening. |

Every scanner flag (F1–F3) and reasoning candidate appears exactly once above.

---

## 5. Findings

### 5.1 [High] Zero committed root makes the empty root acceptable → any unproven message is processable

- **Location:** `Replica.sol:104-113` (`initialize`), consumed at `Replica.sol:201`
  (`process`), `Replica.sol:182-189` (`proveAndProcess`), decided at `Replica.sol:246-259`
  (`acceptableRoot`).
- **Class:** B5 state-machine / sentinel aliasing + B4 authorization (message-auth bypass);
  A6 initialization (`initializer-not-guarded` in the semantic sense of unvalidated init param).
- **Evidence:** E2 — complete source-level adversarial trace (below); not executed (static contract).
- **Root cause:** `initialize` executes `confirmAt[_committedRoot] = 1` with no
  `require(_committedRoot != bytes32(0))`, so the zero root — which is also the default
  value of `messages[hash]` for every unproven message — becomes an *acceptable* root.
- **Proof (ordered):**
  1. `Replica.initialize(..., _committedRoot = 0x0, ...)` ⇒ `confirmAt[0x0] = 1`.
  2. Attacker builds `_message` with `destination = localDomain`, `recipient = BridgeRouter`
     (or `GovernanceRouter`), and attacker-chosen `origin`/`sender`/`nonce`/`body`. It was
     never dispatched, so `messages[keccak(_message)] == 0`.
  3. Attacker calls public `process(_message)`:
     `acceptableRoot(messages[hash]) = acceptableRoot(0)` → `0 != 1`, `0 != 2`,
     `confirmAt[0] == 1 != 0`, `block.timestamp >= 1` ⇒ **true**; the `!proven` guard passes.
  4. `process` calls `recipient.handle(origin, nonce, sender, body)`. `BridgeRouter.handle`
     passes `onlyReplica` (caller is the Replica) and `onlyRemoteRouter` (attacker set
     `origin`/`sender` to an enrolled remote router) → `_giveTokens` mints/releases tokens
     to the attacker. Alternatively `GovernanceRouter.handle` → `_handleBatch` →
     `executeCallBatch` → `_callLocal` runs attacker calldata (e.g. beacon upgrade).
  - Both consumer read-sites (`process`, `proveAndProcess`) reach the same true decision;
    the shortest path is a direct `process` call that skips `prove` entirely.
- **Impact:** total loss of message authentication ⇒ drain of all escrowed/representation
  assets and/or full governance takeover. Same class and root cause as the Aug-2022 Nomad
  incident (~$190M).
- **Confidence:** High that the code permits the state; the exploit is unconditional **given**
  a zero committed root. Severity is **High (Critical impact)** because the trigger is a
  deployment/initialization parameter rather than a runtime attacker input — the contract
  simply fails to forbid the fatal parameter.
- **Fix (minimal):** reject the aliasing at the boundary. In `Replica.initialize` add
  `require(_committedRoot != bytes32(0), "!committedRoot");` and, defensively, make
  `acceptableRoot` return `false` for the zero root unconditionally:
  ```solidity
  function acceptableRoot(bytes32 _root) public view returns (bool) {
      if (_root == bytes32(0)) return false;            // add: zero root never acceptable
      if (_root == LEGACY_STATUS_PROVEN) return true;
      if (_root == LEGACY_STATUS_PROCESSED) return false;
      uint256 _time = confirmAt[_root];
      if (_time == 0) return false;
      return block.timestamp >= _time;
  }
  ```
  Optionally also `require(messages[hash] != bytes32(0))` before `acceptableRoot` in `process`.
- **Validation:** Foundry/Echidna invariant `assertFalse(replica.acceptableRoot(bytes32(0)))`
  across all sequences, plus a PoC test: initialize with `committedRoot = 0`, then assert
  `process(arbitraryMessage)` reverts with `!proven` (see §7 INV-1).

---

## 6. Analysis observations

- **O-1 (C-L3-1, F2) `_handleTransferToHook` unchecked hook call** — `BridgeRouter.sol:378`.
  Intentional and documented; tokens are delivered before the call so the hook, not the
  bridge, bears failure. Unresolved only under a bespoke hook with its own bug; requires the
  specific hook contract to assess. Reentrancy is blocked by the `entered` latch and
  `onlyReplica`. Evidence E1.
- **O-2 (C-L4-2) `executeCallBatch` permissionless trigger** — `GovernanceRouter.sol:474`.
  Safe in isolation (batch must already be `Pending` from an authenticated governance
  message), but it is a downstream amplifier of Finding 5.1: forged governance messages
  become executable arbitrary local calls. Resolve by fixing 5.1. Evidence E1.
- **O-3 (C-L2-3) `Home.update` dequeue loop** — `Home.sol:206`. `improperUpdate` runs first
  and slashes non-queued roots; the unbounded `while(true)` dequeue is a liveness/gas
  consideration, not a fund risk. Evidence E1.
- **O-4 (C-L4-6) `ownerEnrollReplica` missing `_domain != 0`** — `XAppConnectionManager.sol`.
  A domain-0 enrollment would be invisible to `isReplica`. Owner-only, domain 0 invalid;
  hardening only. Evidence E0.
- **O-5 (C-L3-3) `_dust` ignored `.send`** — intentional 2300-gas faucet; no accounting
  effect. Evidence E1.

---

## 7. Invariant catalog

| ID | Invariant | On-chain | Evidence | Fuzz priority |
| --- | --- | --- | --- | --- |
| INV-1 | `acceptableRoot(bytes32(0)) == false` at all times | **No** | `initialize` L112 sets `confirmAt[_committedRoot]=1` unguarded; `acceptableRoot` L253 has no zero-root short-circuit | **high** |
| INV-2 | An unproven message (`messages[hash]==0`) can never satisfy `process` | **No** | `process` L201 feeds default-0 into `acceptableRoot`; violated when INV-1 fails | **high** |
| INV-3 | `messages[hash]` transitions are monotonic: `None → calculatedRoot → PROCESSED`, never reversed | Yes | `prove` blocks re-proving a `PROCESSED` leaf (L241); `process` sets `PROCESSED` (L204) | medium |
| INV-4 | Only the bonded `Updater` can add a confirmable root via `update` | Yes | `Replica.sol:135-139` sig check; `Home` sig+queue | low |
| INV-5 | `confirmAt[root] != 0` ⇒ set only by init / updater `update` / `onlyOwner setConfirmation` | Yes (except INV-1 zero case) | `Replica.sol:112,141,256` write sites enumerated | high (for `root==0`) |
| INV-6 | `handle` (Bridge & Governance) only executes for `onlyReplica` + enrolled remote router | Yes (assuming Replica honest) | `Router.sol:onlyRemoteRouter`, `XAppConnectionClient.onlyReplica` | medium |
| INV-7 | Beacon implementation changes only via `UpgradeBeaconController.upgrade` (`onlyOwner`) / controller | Yes | `UpgradeBeaconController.sol:32`, `UpgradeBeacon.sol:fallback` | low |
| INV-8 | Governance `executeCallBatch` runs only batches marked `Pending` by an authenticated message | Yes | `GovernanceRouter.sol:478`, `_handleBatch` | medium |
| INV-9 | `BridgeToken.permit` requires `ecrecover==owner`, `owner!=0`, nonce++ | Yes | `BridgeToken.sol:155-166` | low |

**Ready-to-use property phrasings for the On-chain=No invariants (fuzz first):**

- **INV-1 (Foundry):**
  ```solidity
  function invariant_zeroRootNeverAcceptable() public {
      assertFalse(replica.acceptableRoot(bytes32(0)));
  }
  ```
- **INV-2 (Foundry PoC / Echidna):**
  ```solidity
  // Setup: replica.initialize(domain, updater, bytes32(0), optimisticSeconds);
  function test_unprovenMessageMustRevert(bytes memory m) public {
      vm.assume(Message.destination(m.ref(0)) == replica.localDomain());
      vm.expectRevert("!proven");
      replica.process(m); // must revert for any never-proven message
  }
  // Echidna property (after correct init with nonzero root):
  function echidna_no_unproven_process() public view returns (bool) {
      return !replica.acceptableRoot(bytes32(0));
  }
  ```
- **INV-5 (Halmos/Certora rule):** for arbitrary `bytes32 r`, `require(r == bytes32(0));`
  assert that after any reachable call sequence `confirmAt[r] == 0` (no initializer or
  setter may write a nonzero `confirmAt[bytes32(0)]`).

---

## Limitations

- **No independent subagent runtime:** all four lanes and the challenge pass were performed
  sequentially by the lead reviewer with separate evidence tables. Recorded, not skipped.
- **Static, source-only** under the security contract: no compilation, execution, fuzzing,
  or PoC deployment. Finding 5.1 is **E2** (explicit source semantics), not E3; INV-1/INV-2
  should be driven to E3 with the tests in §7.
- **External dependencies assumed correct:** `@openzeppelin/*`, `@summa-tx/memview-sol`
  (`TypedMemView`), `MerkleLib` internals — only their call sites were reviewed.
- **Message/encoding libraries** (`BridgeMessage`, `GovernanceMessage`, `Encoding`,
  `libs/Queue`) reviewed for authorization-relevant behavior, not exhaustively for every
  encoding edge case.
- **Deployment/governance keys** (Updater, Owner, RecoveryManager, Watchers) are assumed
  honest per the trust model; their compromise is out of scope but noted as the residual
  trust anchor (slashing is a stub — `UpdaterManager.slashUpdater` only emits `FakeSlashed`).
- Excluded paths (tests/mocks/harnesses, non-Solidity packages) carry **no** coverage claim.

## Related analysis requirements

- Proof-verifier binding → `verifier-bridge-audit`: **not applicable** (no SNARK verifier).
- Circuit soundness → `zk-circuit-review`: **not applicable** (no ZK circuits).

## Completeness declaration

- State-changing entry points mapped: **57/57** in scope (all listed in §2).
- Scanner flags dispositioned: **3/3** (F1 Rejected, F2 Observation, F3 Rejected).
- Reasoning candidates dispositioned: **13/13** (1 Finding, 5 Observations, 7 Rejected).
- Critical/High candidates independently challenged: **1/1** (Finding 5.1 via CH-1; also
  CH-2/3/4 for the High/Medium scanner flags).
- Lanes completed: **5/5** (4 reasoning lanes + 1 challenge).
- **Final status basis:** one E2 finding (5.1) with a complete adversarial trace whose
  precondition (`_committedRoot == 0` at initialization) the contract fails to reject and
  whose realization drains the bridge / seizes governance. Status is **Findings identified**
  on the strength of that trace — not on scanner flag counts (F1/F3 were rejected on manual
  review; zero flags would not have implied safety).
