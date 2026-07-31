# Worked Example

A complete `evm-invariant-scan` 2.0.0 audit of the Nomad bridge at commit
`e7246ea1f17ab49e81d39f199bb17153d3f950d2`.

The skill independently rediscovered the zero-root vulnerability behind the
August 2022 Nomad exploit. `Replica.initialize` accepts a zero committed root;
the default `messages[hash] == bytes32(0)` then passes `acceptableRoot(0)`, so an
attacker can submit an unproven message through the public `process()` path.
The report records the issue at E2: a complete source-connected adversarial
trace.

## Files

- [`report.md`](nomad-monorepo/evm-invariant-scan/report.md): final finding,
  threat model, invariants, limitations, and completeness declaration.
- [`review-ledger.md`](nomad-monorepo/evm-invariant-scan/review-ledger.md): every
  scanner flag and reasoning candidate with its disposition.
- [`scope.md`](nomad-monorepo/evm-invariant-scan/scope.md): pinned revision,
  reviewed paths, exclusions, and commands.
- `enumeration-*.json`: deterministic Phase 1 evidence for the core, bridge, and
  router packages.

This example demonstrates the v2 workflow:

```text
deterministic enumeration
  -> independent reasoning lanes
  -> evidence challenge
  -> mandatory report
```

Machine-specific paths are sanitized to `/opt/audit-targets/nomad-monorepo`.
No target code was compiled or executed during the review.
