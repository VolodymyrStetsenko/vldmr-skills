# ZK Circuit Review — src

> VLDMR Skills · `zk-circuit-review` v1.2.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/semaphore/packages/circuits/src` · 1 file(s) · languages: circom

## Summary

| metric | value |
| --- | ---: |
| Templates / functions | 1 |
| Input signals | 4 |
| Output signals | 1 |
| Equality constraints (`===`/assert) | 1 |
| Assign+constrain (`<==`) | 4 |
| Witness-only assignments (`<--`) | 0 |
| Unconstrained regions | 0 |
| **Leads** | **0** |

## Leads

No heuristic leads. Every declared signal that this scanner can see is referenced by a constraint. This is *not* a proof of soundness — cryptographic-protocol checks (Fiat–Shamir, trusted setup) remain manual.

## Verdict

**Clean surface.** No under-constrained outputs, unused public inputs, or unconstrained regions were detected by static enumeration.

## Method & limits

- Deterministic, comment-stripped source analysis (no proving, no network).
- Leads are heuristic; confirm each with a concrete second witness or a constraint trace before reporting as a finding.
- Library sub-circuits imported from `node_modules`/`target` are not followed.
