---
name: evm-invariant-scan
description: "Pre-audit scan of an EVM/Solidity codebase. Maps entry points and access control, flags permissionless setters, unguarded external calls and unchecked low-level calls, and derives a machine-checkable invariant catalog to seed fuzzing and formal verification. Triggers on 'evm scan', 'pre-audit', 'invariant scan', 'entry points', 'access control map', 'audit prep', 'find invariants'."
---

# EVM Invariant Scan

## Purpose

Enumerate EVM entry points, access controls, state writes, external calls, and
accounting surfaces. Derive invariant candidates suitable for implementation in
Foundry, Echidna, Medusa, Halmos, or Certora.

Resolve `$SKILL_DIR` to the directory containing this file.

Write analysis artifacts under `evm-scan/` at the project root. Do not modify
target source.

## Phase 1 — Enumerate entry points & access

Use the user-specified scope or, when absent, `src/` or
`contracts/`. Run the enumerator:

```bash
mkdir -p evm-scan && python3 "$SKILL_DIR/scripts/enumerate_evm.py" <scope-path> --json evm-scan/enumeration.json --report evm-scan/static-analysis.md && cat evm-scan/enumeration.json
```

The JSON gives, per file: contracts, every function with visibility, mutability,
access modifiers, whether it writes state and whether it makes an external call;
plus `permissionless_entry_points`, `conservation_seeds`, and deterministic
`flags` (`permissionless-config-setter`, `external-call-no-reentrancy-guard`,
`unchecked-low-level-call`, and oracle, flash-loan, or upgradeability flags).
Flags require source-level verification.
The script also writes `evm-scan/static-analysis.md`, a generated
representation of the deterministic enumeration. It is an input to the manual
analysis in Phase 2, not the final assessment. Operational output is written to
standard error; standard output remains machine-readable JSON.

Read `$SKILL_DIR/references/invariant-taxonomy.md` before Phase 2.

## Phase 2 — Derive invariants

Apply the
taxonomy in `references/invariant-taxonomy.md` against the enumeration. Read the
relevant functions before asserting anything.

1. **Confirm every flag.** For each flag, read the function and decide: real
   finding, or acceptable by design? A `permissionless-config-setter` is Critical
   only if the state it writes affects funds or trust; say which. An
   `external-call-no-reentrancy-guard` needs the actual statement order — a
   value-moving call before the state write is the finding.
2. **Conservation.** For each conservation seed (a balance mapping plus a supply
   variable), state the invariant `Σ balances == supply` and check every function
   that writes either side keeps it. A function that writes one without the other
   is both an invariant and a likely bug.
3. **Access & authorization.** For each privileged action, record who can call
   it and whether an instant admin power can extract or redirect funds. Invariant:
   "only `role` can change `X`".
4. **Bounds.** Every parameter with a `require(x <= MAX)` at one setter implies a
   global bound. Check *all* write sites enforce it; an unguarded write site is
   the high-signal gap.
5. **Solvency / accounting.** Contract token balance ≥ sum of user claims; shares
   ↔ assets ratio monotonic where intended; fees never exceed principal.
6. **State machine.** One-shot latches (`require(x == 0); x = v`) and monotonic
   counters are invariants — note any path that violates them.

For each invariant, record: a stable ID, the property, the
variables/functions involved, and whether it is currently **enforced on-chain**
(Yes/No) with the file:line evidence. On-chain=No invariants are the ones to fuzz
first. Classify them as analysis observations until a violating transition is
demonstrated.

## Phase 3 — Write evm-scan report

Write `evm-scan/report.md` per `$SKILL_DIR/references/report-template.md`. It has
three parts: the entry-point/access map, the confirmed findings (ordered by
severity), and the invariant catalog (with On-chain Yes/No and a ready-to-use
phrasing for a verification tool). Classify unverified observations as analysis
observations.

Use `enumeration.json`, `static-analysis.md`, and Phase 2 source review as
inputs. `report.md` is the final analytical deliverable.

Print the report status line after writing the report.

## Constraints

- Execute all phases without user interaction unless scope is ambiguous or a
   required source path is unavailable.
- The enumerator performs static source analysis only. Do not attribute dynamic
   execution or complete semantic coverage to its output.
- ZK circuit soundness and proof-verifier integration are outside scope;
   identify the corresponding analysis dependency when applicable.
