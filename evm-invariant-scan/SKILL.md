---
name: evm-invariant-scan
description: "Pre-audit scan of an EVM/Solidity codebase. Maps entry points and access control, flags permissionless setters, unguarded external calls and unchecked low-level calls, and derives a machine-checkable invariant catalog to seed fuzzing and formal verification. Triggers on 'evm scan', 'pre-audit', 'invariant scan', 'entry points', 'access control map', 'audit prep', 'find invariants'."
---

# EVM Invariant Scan

Before a deep audit — or before writing a fuzz suite — you need a truthful map of
the attack surface and a set of properties worth testing. This skill produces
both: a deterministic enumeration of entry points and access control, and an
invariant catalog phrased so it can be dropped into Foundry invariant tests,
Echidna/Medusa, or Halmos/Certora.

`$SKILL_DIR` is the directory containing this file, resolved from the load path.

Output goes into an `evm-scan/` folder at the project root. Write nothing
outside it.

## Progress tracking (MANDATORY)

Create these todos (all pending), one in progress at a time:

1. `Phase 1: Enumerate entry points & access`
2. `Phase 2: Derive invariants`
3. `Phase 3: Write evm-scan report`

## Phase 1 — Enumerate entry points & access

Mark Phase 1 in progress. Scope: user-specified path, else `src/` or
`contracts/`. Run the enumerator:

```bash
mkdir -p evm-scan && python3 "$SKILL_DIR/scripts/enumerate_evm.py" <scope-path> --json evm-scan/enumeration.json && cat evm-scan/enumeration.json
```

The JSON gives, per file: contracts, every function with visibility, mutability,
access modifiers, whether it writes state and whether it makes an external call;
plus `permissionless_entry_points`, `conservation_seeds`, and deterministic
`flags` (`permissionless-config-setter`, `external-call-no-reentrancy-guard`,
`unchecked-low-level-call`). Flags are leads.

In the same message, preload `$SKILL_DIR/references/invariant-taxonomy.md`.

Mark Phase 1 complete.

## Phase 2 — Derive invariants

Structure comes from the script; the properties come from reasoning. Walk the
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

For each invariant, record: a stable ID, the property in plain terms, the
variables/functions involved, and whether it is currently **enforced on-chain**
(Yes/No) with the file:line evidence. On-chain=No invariants are the ones to fuzz
first — they are candidate bugs.

Mark Phase 2 complete.

## Phase 3 — Write evm-scan report

Write `evm-scan/report.md` per `$SKILL_DIR/references/report-template.md`. It has
three parts: the entry-point/access map, the confirmed findings (ordered by
severity), and the invariant catalog (with On-chain Yes/No and a ready-to-use
phrasing for a fuzzer). No fabrication; mark anything unverified as a lead.

Print the one-line verdict to the terminal at the end.

## Constraints

- Autonomous, single pass.
- The enumerator is static; do not claim coverage or dynamic results.
- ZK circuits and proof-verifier binding are out of scope here — hand those to
  `zk-circuit-review` and `verifier-bridge-audit`.
