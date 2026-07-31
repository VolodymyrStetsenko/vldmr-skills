---
name: verifier-bridge-audit
description: "Audits the seam between a zero-knowledge proof and the EVM: the on-chain verifier contract and every contract that consumes a proof. Finds proof replay, unbound public inputs, verifying-key trust gaps, and malleability at the ZK-to-EVM boundary. Triggers on 'verifier audit', 'proof replay', 'zk bridge audit', 'public input binding', 'audit the verifier', 'nullifier check'."
---

# Verifier Bridge Audit

A sound circuit and a correct verifier can still lose funds if the **binding**
between them is wrong. This skill audits the ZK-to-EVM seam: the on-chain
verifier and, more importantly, the contracts that trust its output. The
recurring failures are: a valid proof that can be spent twice, a proof whose
public inputs are not tied to the actor or state they authorize, and a verifying
key that the wrong party can swap.

`$SKILL_DIR` is the directory containing this file, resolved from the path you
loaded it from.

Output goes into a `bridge-audit/` folder at the project root. Write nothing
outside it.

## Progress tracking (MANDATORY)

Create these todos (all pending), one in progress at a time:

1. `Phase 1: Locate verifiers & consumers`
2. `Phase 2: Audit the binding & trust boundary`
3. `Phase 3: Write bridge-audit report`

## Phase 1 — Locate verifiers & consumers

Mark Phase 1 in progress. Determine scope (user-specified path, else the
contracts directory — `src/` or `contracts/`). Run the locator:

```bash
mkdir -p bridge-audit && python3 "$SKILL_DIR/scripts/scan_verifier.py" <scope-path> --json bridge-audit/scan.json && cat bridge-audit/scan.json
```

The JSON identifies `verifier_contracts` (proof checkers), `consumer_contracts`
(callers of `verify`/`verifyProof`), each verification call site, and
deterministic `flags`: `possible-proof-replay`, `unbound-public-inputs`,
`mutable-verifier`. Treat flags as leads.

In the same message, preload `$SKILL_DIR/references/integration-threats.md`.

Mark Phase 1 complete.

## Phase 2 — Audit the binding & trust boundary

For every consumer call site, read the enclosing function and answer each
question in `references/integration-threats.md`. You MUST read the code before
asserting anything. Focus, in order:

1. **Replay / double-spend.** After a proof verifies, is a unique identifier
   (nullifier, commitment, proof hash, monotonically increasing state) recorded
   and checked *before* the effect, so the same proof cannot succeed twice? A
   nullifier written *after* an external call, or not written at all, is a
   finding. Confirm by describing the exact second call that succeeds.
2. **Public-input binding.** Reconstruct the public-input vector the verifier
   receives and match it, field by field and in order, against what the action
   authorizes. Is the recipient/beneficiary bound into the inputs, or passed as a
   free parameter? Is the amount, the chain id, the contract address, the epoch
   bound? An unbound field is an attacker-chosen field — show how it is abused
   (front-run redirect, cross-contract or cross-chain reuse).
3. **Verifying-key / verifier trust.** Where does the verifying key come from —
   `immutable`, hardcoded, or settable? If settable, what guards the setter
   (timelock, multisig, governance)? A verifier that an EOA admin can swap
   instantly is a single point of proof forgery. Confirm the setter's access
   control and delay.
4. **Input encoding & malleability.** Are proof/point coordinates range-checked
   to the field (points on-curve, scalars `< r`)? Can equivalent encodings of the
   same proof or a different-but-valid proof bypass a de-dup keyed on the raw
   bytes? Keyed replay protection must hash the *public inputs / nullifier*, not
   the malleable proof bytes.
5. **Call ordering (reentrancy at the seam).** Does verification, effect, and
   nullifier write follow checks-effects-interactions? A transfer before the
   nullifier write reopens replay via reentrancy.
6. **Cross-domain reuse.** Do the public inputs pin the proof to this chain,
   this contract, and this version? Missing domain separation lets a proof valid
   on a testnet or a sibling deployment be replayed here.

For each confirmed issue capture: file, line, function, root cause, the concrete
attack sequence (transaction 1 → transaction 2), impact, and the minimal fix.
Unproven suspicions are leads.

Mark Phase 2 complete.

## Phase 3 — Write bridge-audit report

Write `bridge-audit/report.md` per
`$SKILL_DIR/references/report-template.md`. Order by severity. Every finding
carries a concrete two-step (or single-tx) attack trace and a minimal fix.
State clearly which verifier(s) and consumer(s) were in scope. No fabrication.

Print the one-line verdict to the terminal at the end.

## Constraints

- Autonomous, single pass, no user interaction.
- The scanner is static; do not report dynamic results you did not produce.
- This skill covers the *binding*. Circuit soundness is `zk-circuit-review`;
  generic EVM accounting is `evm-invariant-scan`. Note handoffs rather than
  duplicating them.
