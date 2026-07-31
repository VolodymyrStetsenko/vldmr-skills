# Verifier Bridge Audit — Nomad optimistic bridge (`contracts-core` Replica/Home + `contracts-bridge` BridgeRouter)

**Status:** Findings identified

> **Evidence classification:** Scanner flags are source-pattern matches, not
> confirmed vulnerabilities. Promote a flag to a finding only after tracing the
> verifier call, public-input binding, replay state, and reachable impact.

**Target revision:** `e7246ea1f17ab49e81d39f199bb17153d3f950d2` (`feat: add token sender to TransferToHook message (#414)`)
**Tool:** `verifier-bridge-audit` v2.0.0
**Assessment basis:** static enumeration (Phase 1) + manual source review of the optimistic Merkle-proof message boundary (Phases 2–4). No target compilation/execution (security contract).
**"Verifier" contracts (adapted):** `Replica.sol` (`prove`/`acceptableRoot` Merkle-proof acceptance), backed by `NomadBase` (Updater ECDSA) and `libs/Merkle.sol` (`branchRoot`).
**Consumer contracts:** `Replica.process` → `BridgeRouter.handle` (+ `BridgeMessage.sol` decode). Handler auth grounded in `Router.sol` / `XAppConnectionClient.sol` / `XAppConnectionManager.sol`.
**Reviewed:** 2026-07-31 (UTC)

**Scope adaptation:** the target is an **optimistic** bridge with **no ZK/SNARK
verifier**. The proof→EVM boundary is the Merkle-proof-against-accepted-root
check in `Replica`. ZK-only lanes (pairing/point encoding, Fiat–Shamir,
public-signal ordering vs a circuit artifact) are **not applicable** and are
recorded as scope adaptation, not as passes. See `scope.md`.

---

## 1. Statement and integration model

The "public input" is the full formatted message; the leaf committed by the
proof is `leaf = keccak256(message)` where
`message = origin(4) ‖ sender(32) ‖ nonce(4) ‖ destination(4) ‖ recipient(32) ‖ body`.

| Consumer / effect | Call site | Ordered committed inputs (leaf preimage) | Action fields used by effect | Uniqueness | Domain binding | Root/Updater trust |
| --- | --- | --- | --- | --- | --- | --- |
| `Replica.process` → dispatch | `Replica.sol:186`, accept `:192` | `origin, sender, nonce, destination, recipient, body` (all in `leaf`) | `destination` (checked `==localDomain`), `recipient` (handler), `origin/sender/nonce/body` (passed to `handle`) | `messages[leaf]`: `0`→root→`PROCESSED(2)`; `acceptableRoot(PROCESSED)=false` | `destination==localDomain` (`:188`); per-Replica `remoteDomain`; Updater sig over `homeDomainHash(remoteDomain)` | Accepted-root set = `confirmAt` (settable via `update` w/ Updater sig, or `onlyOwner` `setConfirmation`) |
| `BridgeRouter._handleTransfer` → release/mint | `BridgeRouter.sol:118`, `:412` | body ⊃ `TokenId{domain,id}`, `Transfer{recipient, amnt, detailsHash}` | `evmRecipient`, `amnt`, `tokenId` — all from committed body | inherited from `Replica` latch | `onlyReplica` + `onlyRemoteRouter(origin,sender)` | remote router set `onlyOwner` (`remotes`, `router!=0`) |
| `BridgeRouter._handleTransferToHook` → release/mint + hook call | `BridgeRouter.sol:120`, `:377` | body ⊃ `TokenId`, `TransferToHook{hook, amnt, detailsHash, sender, extraData}` | `evmHook`, `amnt`, `sender`, `extraData` — all from committed body | inherited from `Replica` latch | `onlyReplica` + `onlyRemoteRouter` | as above |

**Binding verdict:** every effect-relevant field (recipient/hook, amount,
tokenId, extraData, origin/sender) is committed inside the leaf and re-checked
where it matters (`destination`, `onlyRemoteRouter`). No unbound
caller-controlled field feeds an effect. The one *conditional* break in the
binding is the accepted-root sentinel — Finding **VB-001**.

---

## 2. Review-lane coverage

| Lane | Reviewer | Scope completed | Candidates | Limitations |
| --- | --- | --- | --- | --- |
| Statement reconstruction | lead sequential pass | yes | C-04, C-08, C-10 | TypedMemView revert-on-OOB assumed |
| Replay/ordering | lead sequential pass | yes | C-01, C-02, C-03, C-05 | — |
| Trust/encoding | lead sequential pass | yes | C-01, C-06, C-08, C-09 | UpdaterManager economics not re-derived |
| Effect binding | lead sequential pass | yes | C-07, C-10, C-11 | Hook contracts out of scope (attacker-authored) |
| Independent challenge | lead re-challenge (no subagents) | yes | C-01 | Independent subagents unavailable — recorded limitation |

---

## 3. Candidate accounting

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| F-SCAN | scanner | n/a | verifier/consumer detection | E0 | Not applicable | 0 verifiers/consumers/flags; scanner targets SNARK `verifyProof`, absent here. |
| C-01 | replay/trust | `Replica.sol:262` (+`:29,115,169,192`) | default `messages[hash]==0` must not alias accepted root | E2 | **Finding VB-001 (High)** | zero-root sentinel not rejected; `confirmAt[0]` unguarded at init. |
| C-02 | replay | `Replica.sol:192-197,293-302` | no re-process | E2 | Rejected | `PROCESSED` latch + `acceptableRoot(2)=false`. |
| C-03 | ordering | `Replica.sol:186-205` | no reentrancy | E2 | Rejected | CEI + `entered` guard before `handle`. |
| C-04 | statement | `Replica.sol:186-192` + `Message.sol` | full-message binding | E2 | Rejected | leaf commits all fields; `destination` checked. |
| C-05 | replay/domain | `Replica.sol:299` (`branchRoot`) | forged leaf ↛ real root | E2 | Rejected | keccak second-preimage infeasible; output ≠ 0. |
| C-06 | trust | `Replica.sol:188` | origin bound to home | E1 | Observation (Low) | no `origin==remoteDomain` assert; covered by `onlyRemoteRouter`. |
| C-07 | effect | `BridgeRouter.sol:377-405` | hook call ordering | E1 | Observation (Low) | tokens before ignored-result `call`; documented design; funds-stranding only. |
| C-08 | encoding | `BridgeMessage.sol` | type/length safety | E2 | Rejected | `isValidMessageLength` + `typeAssert` + in-bounds slices. |
| C-09 | trust | `Replica.sol:145,249`; `NomadBase` | root/updater mutability | E1 | Observation | governance/Updater trust model; trigger surface for VB-001. |
| C-10 | effect | `BridgeRouter.sol:412-459` | mint/release recipient bound | E2 | Rejected | recipient/amount/tokenId all from committed body. |
| C-11 | handler-auth | `BridgeRouter.sol:104-124` | only cross-chain msgs reach effects | E2 | Rejected | `onlyReplica` + `onlyRemoteRouter`. |

Every scanner flag and reasoning candidate appears exactly once (see
`review-ledger.md`).

---

## 4. Findings

### [High] VB-001 — Zero-root sentinel not rejected: unproven-message acceptance re-enabled by an unguarded `confirmAt[0]` (Nomad-class)

- **Location:** `packages/contracts-core/contracts/Replica.sol:262` — `acceptableRoot`; state read at `packages/contracts-core/contracts/Replica.sol:192` (`process`) and `packages/contracts-core/contracts/Replica.sol:169` (`proveAndProcess`); enabling write at `packages/contracts-core/contracts/Replica.sol:115` (`initialize`).
- **Class:** Threat #2 (under-bound / sentinel aliasing) + Threat #4 (initialization/root-trust).
- **Evidence:** E2 — complete code-level acceptance trace; the only missing link is a privileged/misconfiguration write of `confirmAt[0]`.
- **Root cause:** `acceptableRoot` explicitly rejects `LEGACY_STATUS_PROCESSED(2)` and accepts `LEGACY_STATUS_PROVEN(1)` but does **not** reject `bytes32(0)`; the declared constant `LEGACY_STATUS_NONE = bytes32(0)` (`packages/contracts-core/contracts/Replica.sol:29`) is never used. For any never-proven message `messages[hash]` is the storage default `0`, so `process` evaluates `acceptableRoot(0)`, whose result is `true` whenever `confirmAt[0] != 0`. `initialize` unconditionally sets `confirmAt[_committedRoot] = 1` with **no** `require(_committedRoot != 0)`, so a zero committed root (deploy/upgrade misconfiguration, or governance/Updater setting root `0`) makes `confirmAt[0] = 1` and thereby marks *every* unproven message acceptable.
- **Attack trace:**
  1. Precondition (privileged/misconfig): a `Replica` is initialized (or re-initialized on upgrade) with `_committedRoot == bytes32(0)`, or governance `setConfirmation(0, t)` / an Updater update to `_newRoot == 0` runs — any of these sets `confirmAt[bytes32(0)] != 0`. This is the exact condition that occurred in the 2022 Nomad incident.
  2. Tx 1 (unprivileged): attacker calls `Replica.process(forgedMessage)` where `forgedMessage.destination == localDomain` and `origin`/`sender` are set to an enrolled remote `BridgeRouter` (public). `messages[keccak256(forgedMessage)] == 0`, `acceptableRoot(0) == true` ⇒ the "!proven" check passes; `process` dispatches to `BridgeRouter.handle`, which passes `onlyReplica` (caller is the Replica) and `onlyRemoteRouter`, then mints/releases `amnt` tokens to the attacker-chosen `recipient`/`hook`. Repeat for every token/amount → full drain.
- **Impact:** Total loss of bridged funds (arbitrary mint of representation tokens and release of escrowed canonical tokens) once `confirmAt[0]` is non-zero. Blast radius = entire Replica.
- **Confidence:** High for the code defect and the drain mechanics; the *trigger* requires a privileged action or deployment/upgrade misconfiguration (no unprivileged writer of `confirmAt[0]` exists), which is why this is rated **High** rather than **Critical**. It becomes **Critical** for any deployment/upgrade path that can pass a zero committed root.
- **Fix (minimal, defense-in-depth at the sink):** hard-reject the sentinel in `acceptableRoot`:
  ```solidity
  function acceptableRoot(bytes32 _root) public view returns (bool) {
      if (_root == LEGACY_STATUS_NONE) return false;      // <-- add
      if (_root == LEGACY_STATUS_PROVEN) return true;
      if (_root == LEGACY_STATUS_PROCESSED) return false;
      uint256 _time = confirmAt[_root];
      if (_time == 0) return false;
      return block.timestamp >= _time;
  }
  ```
  and enforce the precondition at the source: in `initialize`, `require(_committedRoot != bytes32(0), "!root")` before `confirmAt[_committedRoot] = 1` (and reject `_newRoot == 0` in `update`).
- **Validation:** unit test — deploy a Replica with `_committedRoot = 0`, then assert `process(anyForgedMessage)` reverts with `"!proven"`; and a test asserting `acceptableRoot(bytes32(0)) == false` regardless of `confirmAt[0]`.

---

## 5. Analysis observations

- **C-06 (Low) — `Replica.process` does not assert `origin == remoteDomain`** (`packages/contracts-core/contracts/Replica.sol:188`). A legit accepted root is domain-bound via the Updater signature over `homeDomainHash(remoteDomain)`, and the downstream `Router.onlyRemoteRouter(origin, sender)` requires `remotes[origin] == sender && sender != 0`, so a spoofed `origin` cannot reach an effect. Adding an explicit `origin == remoteDomain` check would be defense-in-depth. *Evidence to escalate:* a reachable handler that trusts `origin` without an enrolled-remote check.
- **C-07 (Low) — TransferToHook sends tokens before an ignored-result hook call** (`packages/contracts-bridge/contracts/BridgeRouter.sol:377`). `_giveTokens(..., _hook)` runs before `_hook.call(_call)`, whose success and code-existence are intentionally ignored (documented). No authorization bypass; risk is funds stranded in a non-existent/reverting hook. *Evidence to escalate:* a state change in `BridgeRouter` gated on hook success (none found).
- **C-09 — Root/Updater mutability is the trust model, and the trigger surface for VB-001.** `setConfirmation`/`setUpdater` are `onlyOwner`; roots enter via bonded-Updater ECDSA. Acceptable under optimistic security, but note that governance or a compromised Updater is precisely what can arm VB-001 by writing `confirmAt[0]`.

---

## Limitations

- **No dynamic validation:** target not compiled or executed (security contract). Findings are established by source trace; VB-001's exploit is argued at the code level, not reproduced on-chain.
- **Independent subagents unavailable:** the Critical/High challenge for VB-001 was performed by the lead reviewer as a separate pass (recorded in `review-ledger.md`), not by an independent agent.
- **External libraries assumed correct:** `@summa-tx/memview-sol` `TypedMemView` revert-on-out-of-range behavior (relied on for `BridgeMessage` bounds safety) and OpenZeppelin ECDSA/`Initializable`/`Ownable` were not re-audited.
- **Out of scope / not re-derived:** `TokenRegistry`, `BridgeToken`, `Encoding`, `ETHHelper`, `governance/`, `upgrade/`, `UpdaterManager` slashing economics, and the `contracts-router` base beyond the `onlyReplica`/`onlyRemoteRouter`/`_mustHaveRemote` semantics quoted above.
- The scanner produced zero flags; this reflects absence of a SNARK verifier pattern, **not** a safety result. All boundary conclusions here are from manual review.

## Related analysis requirements

- Circuit-side concerns — **not applicable** (no ZK circuit). If a future version adds a SNARK light-client, route to `zk-circuit-review`.
- Generic accounting / access-control (e.g. `TokenRegistry` representation mapping, escrow accounting, Updater bonding) → `evm-invariant-scan`.

## Completeness declaration

- Verifiers reviewed: `1/1` (the `Replica` Merkle-proof acceptance path; no SNARK verifier exists).
- Consumers and proof-dependent effects reviewed: `3/3` (`process`→dispatch, `_handleTransfer`, `_handleTransferToHook`).
- Verification/acceptance call sites field-mapped: `3/3` (`proveAndProcess:169`, `process:192`, `prove:299`).
- Scanner flags and reasoning candidates dispositioned: `12/12` (1 scanner N/A + 11 reasoning candidates).
- Critical/High candidates independently challenged: `1/1` (VB-001; lead re-challenge — subagent limitation noted).
- Lanes completed: `5/5`.
- Final status basis: one E2 High finding (VB-001) plus a fully field-mapped binding table showing all other effect fields are proof-committed and replay is latched; status is **Findings identified**. Zero scanner flags is explicitly not the basis.
