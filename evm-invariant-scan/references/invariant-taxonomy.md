# EVM Invariant Taxonomy

The reference model for `evm-invariant-scan`. It has two jobs: classify the
deterministic flags from the enumerator, and provide a structured way to derive
invariants worth fuzzing or formally verifying.

An **invariant** is a property that must hold across *any* sequence of calls
(e.g. "Σ balances == totalSupply"). A **guard** is a per-call precondition
(`require(amount > 0)`); it is true by construction at that call site and is not,
by itself, falsifiable. The valuable output is the invariant whose enforcement is
**incomplete** — true at some write sites, missing at others.

---

## A. Flag classes (confirm the enumerator's leads)

### A1. Permissionless config setter
A state-changing setter with no access modifier. **Critical** if the state
affects funds, pricing, oracles, or trust (`setFee`, `setOracle`, `setOwner`);
**Low** if it is a genuinely user-scoped, self-only value. Confirm by reading
what the written variable controls.

### A2. External call without reentrancy guard
A permissionless function that calls out. **Finding** when a value-moving
external call precedes the state update that should have closed the position
(CEI violation) — trace the statement order. **Note only** if effects fully
precede interactions.

### A3. Unchecked low-level call
`.call`/`.delegatecall` whose success boolean is ignored, silently swallowing
failures (lost funds, desynced state). Confirm the return is truly unhandled.

---

## B. Invariant classes (derive and classify On-chain Yes/No)

### B1. Conservation
`Σ mapping[k] == scalar` (balances vs supply, shares vs totalShares). For every
function that writes either side, both must move together. A single-sided write
is a conservation break — record it as On-chain=No with the offending line.

### B2. Bounds
A value constrained at one site (`require(fee <= MAX)`) implies a global bound
`fee ∈ [0, MAX]`. Enumerate *all* write sites of the variable; if any writes it
without the check, the bound is On-chain=No — simultaneously an invariant and a
candidate bug.

### B3. Solvency / accounting
`address(this).balance >= Σ withdrawable`, or `assets >= liabilities`. Payout,
fee, and rounding paths are the usual violators. Rounding must always favor the
protocol, never the caller.

### B4. Authorization
"Only `role` can perform `action`." Derive from modifiers and internal
`msg.sender` checks. Invariant is On-chain=No if any path reaches the action
without the check (missing modifier, delegatecall, or a public internal helper).

### B5. State machine / monotonicity
One-shot latches (`require(x == default); x = v`), monotonic counters/nonces,
and "initialized once" flags. Invariant broken if any function reverses a
one-way transition or resets a monotonic value.

### B6. Ratio / exchange rate
`price = reserveA * k / reserveB` style relations, share-price monotonicity.
Note whether snapshots are taken before or after other state changes in the same
function — ordering is where these break.

### B7. Temporal
Deadlines, cooldowns, and lock periods that compare `block.timestamp` /
`block.number` against stored state. Broken by check-then-update vs
update-then-check ordering and by unbounded admin-settable durations.

---

## C. Phrasing invariants for tooling

For each derived invariant, provide a phrasing that can be pasted into a test:

- **Foundry invariant test:** `assertEq(sumBalances(), token.totalSupply());`
- **Echidna/Medusa property:** `function echidna_supply_matches() public view
  returns (bool) { return sumBalances() == totalSupply; }`
- **Halmos/Certora rule:** state the property over arbitrary inputs and a
  `require` precondition.

Prioritize On-chain=No invariants for fuzzing — they are the ones the code does
not already guarantee.

---

## Severity guidance

- **Critical** — an invariant break that lets an attacker extract value now
  (broken conservation on a withdrawal path, permissionless fund-affecting
  setter, exploitable reentrancy).
- **High** — a break reachable under a plausible precondition, or an
  authorization gap on a privileged action.
- **Medium** — an incomplete bound with no current exploit, an unchecked call on
  a non-critical path.
- **Low** — hardening and defense-in-depth.
- **Lead** — a suspected invariant break you could not yet demonstrate.
