# EVM Invariant Scan — src

> VLDMR Skills · `evm-invariant-scan` v1.2.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/world-id-contracts/src` · 19 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Contracts | 19 |
| Functions | 146 |
| Entry points (external/public) | 17 |
| Permissionless entry points | 3 |
| Conservation seeds (supply vs. balances) | 0 |
| **Leads** | **0** |

## Leads

No heuristic leads. No permissionless config setters, unguarded external calls, oracle/flash-loan/upgrade risks were detected. This is a surface map, not a proof of correctness — confirm invariants with fuzzing.

## Invariant seeds

Suggested properties to encode for fuzzing / formal review:

- **Access control:** 3 permissionless entry point(s) — confirm each is intentionally public.
- **Monotonicity / solvency:** encode any documented "never decreases" or "assets ≥ liabilities" property as an Echidna/Medusa invariant.

## Verdict

**Clean surface.** No permissionless-setter, reentrancy, oracle, flash-loan, or upgrade leads were detected by static enumeration.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Leads are structural; a flagged pattern is not proof of a bug, and an absent flag is not proof of safety. Pair with fuzzing and manual review.
