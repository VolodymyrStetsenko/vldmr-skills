# ZK-to-EVM Integration Threats

The reference model for `verifier-bridge-audit`. These are boundary bugs: the
circuit may be sound and the verifier correct, yet the *consumer* misuses the
result. Each entry gives the failure, the confirmation test, and the fix.

---

## 1. Proof replay / double-spend

**Failure.** A valid proof is accepted more than once because nothing marks it
consumed. Variants: no nullifier at all; a nullifier written *after* the value
transfer (reentrancy re-entry); a de-dup keyed on malleable proof bytes instead
of the nullifier/public inputs.

**Confirm.** Describe the exact second transaction that reuses the same proof (or
the reentrant call within the first) and still passes every `require`.

**Fix.** Derive a unique nullifier from the public inputs, `require` it unused,
and mark it used **before** any external interaction (checks-effects-
interactions). Never key replay protection on the proof bytes.

---

## 2. Unbound / under-bound public inputs

**Failure.** The action authorized by the proof depends on data that is *not* in
the public-input vector. The most common form: `recipient`, `amount`, or
`msg.sender` is a free function parameter while the proof only attests to a
Merkle root or nullifier. Anyone who observes the proof can resubmit it with
their own parameters.

**Confirm.** Reconstruct the public-input vector and show a field that the
handler treats as authorized but the verifier never received. Then give the
front-run/redirect transaction that abuses it.

**Fix.** Bind every security-relevant value into the public inputs (recipient,
amount, chain id, contract address, epoch/nonce). The verifier must reject any
proof whose public inputs disagree with the on-chain action.

---

## 3. Public-input ordering / layout mismatch

**Failure.** The consumer packs public inputs in a different order (or count)
than the circuit produced them. The pairing check still passes for *some*
assignment, so a forged mapping of inputs is accepted.

**Confirm.** Diff the circuit's declared public-signal order against the array
the consumer passes to `verifyProof`. Any mismatch in order, count, or endianness
is a finding.

**Fix.** Generate the input layout from the circuit artifact; assert the array
length; document the exact field order.

---

## 4. Verifying-key / verifier trust

**Failure.** The verifying key or verifier address is mutable by an
insufficiently trusted party, or does not correspond to the audited circuit. A
swapped verifier accepts forged proofs for everything downstream.

**Confirm.** Locate the VK source (`immutable`, constant, or setter). If
settable, identify the access control and any delay. An instant EOA-controlled
setter is Critical; a timelocked/governance setter is acceptable but noted.

**Fix.** Prefer an `immutable` VK pinned to the circuit hash. If upgradeability
is required, gate it behind a timelock and emit an event; document the circuit
version each VK corresponds to.

---

## 5. Proof / point malleability

**Failure.** Proof elements are not validated to lie in the correct groups/fields
(points on-curve and in the right subgroup, scalars `< r`). Malleable encodings
let an attacker produce a distinct-but-valid proof that bypasses a byte-keyed
de-dup, re-enabling replay.

**Confirm.** Show that replay protection keys on mutable proof bytes, or that
point/scalar validation is missing where the verifier does not enforce it.

**Fix.** Validate group membership (or rely on a verifier that does), and key all
replay protection on the nullifier / public inputs.

---

## 6. Cross-domain reuse (missing domain separation)

**Failure.** A proof valid in one context is replayed in another: another chain,
a sibling deployment, a previous contract version. The public inputs do not pin
the domain.

**Confirm.** Show the public inputs omit chain id, contract address, or version,
and describe the cross-domain replay.

**Fix.** Include a domain separator (chain id + contract address + version) in
the public inputs or the nullifier derivation.

---

## 7. Ordering at the seam (CEI violations)

**Failure.** The consumer verifies, then transfers value, then records the
nullifier — or performs an external call between verification and the state
write. Reentrancy replays the proof before it is marked used.

**Confirm.** Trace the statement order around the call site; a value-moving
external call before the nullifier write is the finding.

**Fix.** Verify → record nullifier / update state → then interact. Add a
reentrancy guard where external calls are unavoidable mid-flow.

---

## 8. Signal / semantics drift between circuit and contract

**Failure.** The contract interprets a public output differently from what the
circuit proves (e.g. treats a field element as a bounded amount without a range
constraint, or assumes a boolean the circuit never constrained). This is the
mirror image of the circuit's public-I/O class — audit both ends.

**Confirm.** Compare the contract's assumptions about each public value with the
constraints the circuit actually imposes (cross-reference `zk-circuit-review`
output when available).

**Fix.** Align semantics: constrain in-circuit what the contract assumes, or
re-validate on-chain what the circuit does not guarantee.

---

## Severity guidance

- **Critical** — direct value loss: replayable withdrawal, unbound recipient,
  instantly swappable verifier, accepted forged proof.
- **High** — value loss under a plausible precondition, or cross-domain replay.
- **Medium** — missing domain separation with no current second deployment,
  malleability with byte-keyed de-dup not yet exploited, timelock too short.
- **Low** — hardening: undocumented input ordering, event/telemetry gaps.
- **Lead** — a boundary weakness you could not turn into a concrete tx sequence.

---

## Detector coverage & limits (`scan_verifier.py`)

What the static scanner recognizes, so a reviewer knows where manual work
begins:

- **Verifier detection.** Both classic snarkjs / hand-written Solidity templates
  (`Pairing`, `snark_scalar_field`, hex precompile `0x08`) **and** modern
  optimized Yul verifiers that inline the precompiles with decimal ids
  (`staticcall(..., 8, ...)`, `pPairing`/`checkPairing`). A file is treated as a
  verifier when ≥2 markers match.
- **Replay guard (threat 1).** Recognized idioms: `require(!used[x])`; custom
  errors (`revert AlreadyUsed()/...Twice/...Spent`); conditional reverts
  (`if (nullifiers[x]) revert/require`); and consume-writes
  (`nullifiers[x] = true`, `.nullifiers[x] = true`). Missing tracking **or**
  missing guard raises `possible-proof-replay`.
- **Context binding (threat 2).** A proof is considered bound when its public
  arguments to `verifyProof(...)` commit to caller/recipient/scope/domain data
  (`msg.sender`, `nullifier`, `scope`, `recipient`, `domain*`, `chainid`,
  `address(this)`), or the enclosing function explicitly checks `msg.sender`. A
  term that merely appears elsewhere in the body (e.g. a `recipient` parameter
  **not** passed into the proof) does not count — that is the case that raises
  `unbound-public-inputs`.
- **Limits.** The scanner does not follow public-input *ordering* (threat 3),
  point malleability (threat 5), or transcript/Fiat–Shamir soundness — these
  remain manual. Every flag is a lead to confirm against the real data flow.
