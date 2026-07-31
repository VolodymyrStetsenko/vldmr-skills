# Review Ledger — verifier-bridge-audit

Target `e7246ea1`. Evidence levels per `references/reasoning-workflow.md`
(E0 candidate / E1 observation / E2 finding / E3 confirmed). Every scanner flag
and reasoning candidate appears exactly once.

## Scanner flags

| ID | Origin | Location | Disposition | Reason |
| --- | --- | --- | --- | --- |
| F-SCAN | scanner (core+bridge) | n/a | Not applicable (scope adaptation) | 0 verifiers/consumers/flags; scanner targets SNARK `verifyProof`/pairing, absent in optimistic Merkle bridge. Manual review substituted. |

## Reasoning candidates

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| C-01 | trust/replay lane | `Replica.sol:262` `acceptableRoot` + reads `:169,192`, write `:115` | Default `messages[hash]==0` must NOT alias an accepted root | E2 | **Finding (High)** | `acceptableRoot` special-cases `LEGACY_STATUS_PROVEN(1)`/`PROCESSED(2)` but not `0`; `LEGACY_STATUS_NONE=bytes32(0)` (`:29`) is declared yet unused. Sole guard is `confirmAt[0]==0`, and `initialize` writes `confirmAt[_committedRoot]=1` (`:115`) with no `_committedRoot!=0` check. If `confirmAt[0]!=0`, `process()` accepts any unproven message → total drain. Nomad-class. |
| C-02 | replay lane | `Replica.process:192-197`, `prove:293-302` | A proven/processed message cannot be re-processed | E2 | Rejected | `process` sets `messages[hash]=LEGACY_STATUS_PROCESSED(2)` (`:197`) *before* `handle`; `acceptableRoot(2)` returns `false` (`:266`); `prove` requires `messages[leaf]!=PROCESSED`. Replay latched. |
| C-03 | ordering lane | `Replica.process:186-205` | No reentrancy re-entry at the seam | E2 | Rejected | CEI honored: status write + `entered=0` occur before external `handle`; reentrant `process` reverts on `entered==1`; reentrant reuse of same hash reverts on `acceptableRoot(PROCESSED)=false`. |
| C-04 | statement lane | `Replica.process:186-192`, `Message.sol` leaf | Every effect field is committed by the proof | E2 | Rejected | Leaf = `keccak256(message)`, message = origin‖sender‖nonce‖dest‖recipient‖body. Proof binds all of them; `process` checks `destination==localDomain`. Effect fields fully bound. |
| C-05 | replay/domain lane | `prove:299` `branchRoot` | Forged leaf cannot map to a legit accepted root | E2 | Rejected | `branchRoot` is 32 keccak rounds; second-preimage to a real nonzero root is infeasible; output is effectively never `0`. Merkle binding sound. Forgery only via the C-01 `confirmAt[0]` alias (direct storage default, not via `branchRoot`). |
| C-06 | trust lane | `Replica.process:188` | Origin field bound to this Replica's home | E1 | Observation (Low) | `process` does not assert `_m.origin()==remoteDomain`; mitigated downstream by `Router.onlyRemoteRouter(_origin,_sender)` (`remotes[origin]==sender && sender!=0`). Defense-in-depth gap only. |
| C-07 | effect lane | `BridgeRouter._handleTransferToHook:360-405` | Effect ordering / call handling | E1 | Observation (Low, documented design) | Tokens sent to `_hook` before `_hook.call`; success & existence ignored by design (comment). Funds can be stranded in a non-existent/reverting hook, but no auth bypass. |
| C-08 | encoding lane | `BridgeMessage.sol` (`action`, `evmRecipient`, `amnt`, `sender`, `extraData`) | Type/length safety of message decode | E2 | Rejected | `mustBeMessage`→`isValidMessageLength` pins Transfer len==133 and hook len>=165; `typeAssert` guards field readers; action type derived from the same wire byte for both `actionType` and view type; slice offsets within bounds (extraData length ≥0). No truncation/overlap. |
| C-09 | trust lane | `Replica.setConfirmation:249`, `update:145`, `NomadBase._setUpdater` | Accepted-root / updater mutability | E1 | Observation (accepted trust model) | `setConfirmation`/`setUpdater` are `onlyOwner` (governance); `update` admits roots via bonded-Updater ECDSA over `homeDomainHash‖oldRoot‖newRoot`. Optimistic-security model; also the privileged trigger surface for C-01. |
| C-10 | effect lane | `BridgeRouter._giveTokens:412-459` | Mint/release recipient bound | E2 | Rejected | Recipient/hook read from committed `_action`; amount from committed `_action.amnt()`; tokenId from committed message. No unbound caller parameter. |
| C-11 | handler-auth lane | `BridgeRouter.handle:104-124` | Only genuine cross-chain messages reach effects | E2 | Rejected | `onlyReplica` (enrolled Replica) + `onlyRemoteRouter` (enrolled remote router, `router!=0`). Direct external `handle` calls blocked. |

## Challenge record (Critical/High)

C-01 was independently re-challenged (single lead reviewer; independent
subagents unavailable — recorded as a limitation). Challenge checks:
- **Reachability of the read:** `process()` is `public`; `messages[hash]` for a
  never-proven leaf is the storage default `0`; `acceptableRoot(0)` is consulted
  directly (not via `branchRoot`). Confirmed reachable by any caller.
- **Every read site of the alias enumerated:** `proveAndProcess:169`
  (`acceptableRoot(messages[hash])` first disjunct), `process:192`, and the
  `prove:299` path (rejected — `branchRoot`≠0). The exploitable read is
  `process`/first disjunct.
- **Every write site of `confirmAt[0]` enumerated:** `initialize:115`
  (`confirmAt[_committedRoot]=1`, no non-zero guard), `update:145`
  (`confirmAt[_newRoot]`, needs Updater sig), `setConfirmation:249` (`onlyOwner`).
  No *unprivileged* writer — trigger is a privileged/misconfiguration precondition
  ⇒ severity **High**, not Critical; **Critical if** any deploy/upgrade path
  passes a zero committed root (the historical Nomad trigger).
- **Not rejected on a single path:** the normal-init (nonzero root) path blocks
  it, but the guard omission + unconditional `confirmAt[_committedRoot]=1` keep
  the catastrophic state one privileged step away. Retained as a finding per the
  sentinel-aliasing discipline.
