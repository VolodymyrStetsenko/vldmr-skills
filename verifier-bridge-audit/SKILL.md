---
name: verifier-bridge-audit
description: "Audits the seam between a zero-knowledge proof and the EVM: the on-chain verifier contract and every contract that consumes a proof. Finds proof replay, unbound public inputs, verifying-key trust gaps, and malleability at the ZK-to-EVM boundary. Triggers on 'verifier audit', 'proof replay', 'zk bridge audit', 'public input binding', 'audit the verifier', 'nullifier check'."
license: MIT
compatibility: "Requires Python 3.9 or later. Static analysis uses the standard library only and does not require network access or target execution."
metadata:
   author: Volodymyr Stetsenko
   version: "1.0.0"
---

# Verifier Bridge Audit

## Purpose

Assess the integration between an on-chain proof verifier and contracts that
consume its result. The analysis covers replay protection, public-input
binding, verifier and verifying-key trust, encoding, and call ordering.

Resolve `$SKILL_DIR` to the directory containing this file.

Write analysis artifacts under `bridge-audit/` at the project root. Do not
modify target source.

## Phase 1 — Locate verifiers & consumers

Determine scope from the user-specified path or, when absent, the
contracts directory — `src/` or `contracts/`). Run the locator:

```bash
mkdir -p bridge-audit && python3 "$SKILL_DIR/scripts/scan_verifier.py" <scope-path> --json bridge-audit/scan.json --report bridge-audit/static-analysis.md && cat bridge-audit/scan.json
```

The JSON identifies `verifier_contracts` (proof checkers), `consumer_contracts`
(callers of `verify`/`verifyProof`), each verification call site, and
deterministic `flags`: `possible-proof-replay`, `unbound-public-inputs`,
`mutable-verifier`. Treat flags as machine-readable pattern matches requiring source-level
verification. The script also writes
`bridge-audit/static-analysis.md`, a generated representation of the
deterministic scan. It is an input to the manual analysis in Phase 2, not the
final assessment. Operational output is written to standard error; standard
output remains machine-readable JSON.

Read `$SKILL_DIR/references/integration-threats.md` before Phase 2.

## Phase 2 — Audit the binding & trust boundary

For every consumer call site, inspect the enclosing function and apply each
control in `references/integration-threats.md`. Use the following priority:

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

For each confirmed issue, record: file, line, function, root cause, the concrete
attack sequence (transaction 1 → transaction 2), impact, and the minimal fix.
Classify observations without a demonstrated attack path as analysis observations.

## Phase 3 — Write bridge-audit report

Write `bridge-audit/report.md` per
`$SKILL_DIR/references/report-template.md`. Order by severity. Every finding
carries a concrete two-step (or single-tx) attack trace and a minimal fix.
State which verifier and consumer contracts were in scope and identify all
scope exclusions.

Use `scan.json`, `static-analysis.md`, and Phase 2 source review as inputs.
`report.md` is the final analytical deliverable.

Print the report status line after writing the report.

## Constraints

- Execute all phases without user interaction unless scope is ambiguous or a
   required source path is unavailable.
- The scanner performs static source analysis only. Do not attribute dynamic
   execution or complete semantic coverage to its output.
- Circuit soundness and generic EVM accounting are outside scope; identify the
   corresponding `zk-circuit-review` or `evm-invariant-scan` analysis dependency.
