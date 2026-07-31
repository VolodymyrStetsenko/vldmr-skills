# Reference Audit — Worked Example (v2.0.0)

This directory contains a **complete, real audit** produced by the autonomous
`2.0.0` skill workflows, kept so anyone evaluating the tool can see exactly what
it does and what it produces — end to end, on a real protocol.

The example target is the **Nomad optics-style cross-chain bridge** at its
pre-incident revision. In August 2022 this codebase suffered a ~$190M exploit
whose root cause was a *zero committed root* that made unproven messages
acceptable. These artifacts show the skills **independently rediscovering that
exact bug from source alone** — no exploit write-ups, no test execution, no
prior knowledge — as a demonstration of the workflow and its evidence
discipline.

> Earlier releases shipped only deterministic scanner output (enumeration JSON +
> a markdown restatement). Those v1 artifacts have been removed. This example
> shows the full v2 workflow: deterministic enumeration → independent reasoning
> lanes → evidence-lattice challenge → mandatory report.

## Target revision

| Target | Repository | Commit |
| --- | --- | --- |
| Nomad monorepo | `nomad-xyz/monorepo` | `e7246ea1f17ab49e81d39f199bb17153d3f950d2` |

Scope: `packages/contracts-core/contracts`, `packages/contracts-bridge/contracts`,
`packages/contracts-router/contracts` (tests, mocks, and harnesses excluded).

## What the tool found

Two skills were run against the same protocol and **both independently reached
the same root cause** by different routes:

| Skill | Headline result | Route |
| --- | --- | --- |
| `evm-invariant-scan` | **High (critical impact)** — zero committed root makes the empty root acceptable, so any unproven message is processable | State/lifecycle lanes → shortest public `process()` path |
| `verifier-bridge-audit` | **High** — zero-root sentinel not rejected in `acceptableRoot`; unproven-message acceptance re-enabled by an unguarded `confirmAt[0]` | Optimistic Merkle-proof message boundary |

Root cause in one line: `Replica.initialize` runs `confirmAt[_committedRoot] = 1`
with no `require(_committedRoot != 0)` guard. Because `messages[hash]` defaults
to `bytes32(0)` for any never-proven message and `acceptableRoot(0)` has no
zero-root short-circuit, the empty root is treated as confirmed and
`process(arbitraryMessage)` dispatches attacker-controlled messages to
`BridgeRouter` / `GovernanceRouter`.

Both findings are recorded at evidence level **E2** (a complete adversarial
trace), the level the workflow requires before anything is called a finding.

## Artifact index

Each skill run writes the same artifact set. Read them in order to follow the
reasoning from raw enumeration to the confirmed finding.

| Read order | File | What it is |
| --- | --- | --- |
| 1 | `scope.md` | pinned revision, included/excluded paths, exact commands, scanner flags |
| 2 | `static-analysis-*.md` | human-readable restatement of the deterministic enumeration |
| 3 | `enumeration-*.json` / `scan-*.json` | machine-readable enumeration (the evidence input, **not** the assessment) |
| 4 | `review-ledger.md` | every scanner flag and reasoning candidate with one disposition (Finding / Observation / Rejected) |
| 5 | `report.md` | the mandatory final report: threat model, access map, findings with E2 proof, invariant catalog, completeness declaration |

```
nomad-monorepo/
├── evm-invariant-scan/
│   ├── report.md              ← start here (the finding + proof)
│   ├── review-ledger.md
│   ├── scope.md
│   ├── static-analysis-core.md, static-analysis-bridge.md, static-analysis-router.md
│   └── enumeration-core.json, enumeration-bridge.json, enumeration-router.json
└── verifier-bridge-audit/
    ├── report.md
    ├── review-ledger.md
    ├── scope.md
    ├── static-analysis-core.md, static-analysis-bridge.md
    └── scan-core.json, scan-bridge.json
```

## Reproduce it

The autonomous workflow is driven by an agent that reads the skill's `SKILL.md`
and executes its phases. The deterministic Phase-1 enumeration — the reproducible
evidence base under every report — can be regenerated directly:

```bash
# from the checked-out target repository root, at the revision above
python3 evm-invariant-scan/scripts/enumerate_evm.py packages/contracts-core/contracts \
  --json enumeration-core.json --report static-analysis-core.md --no-banner

python3 verifier-bridge-audit/scripts/scan_verifier.py packages/contracts-core/contracts \
  --json scan-core.json --report static-analysis-core.md --no-banner
```

The reasoning lanes, evidence-lattice challenge, and `report.md` are produced by
the agent following `SKILL.md`; see each skill's `references/reasoning-workflow.md`
for the evidence rules (E0–E3) that gate a finding. The JSON records the
deterministic enumeration; report dates and absolute paths vary by environment.

## Honest-scope notes

- `verifier-bridge-audit` was run on a protocol with **no ZK/SNARK verifier**; its
  ZK-specific lanes are recorded as *not applicable* (scope adaptation), never as
  passes. The skill still audited the optimistic Merkle-proof message boundary.
- These reports are static, source-only (no compilation or execution, per the
  security contract). Each report lists ready-to-run Foundry/Echidna/Halmos
  properties to drive the finding to an executable proof (E3).

## Publication policy

`examples/` is publicly publishable. Generated artifacts here have been
sanitized: machine-specific absolute paths and usernames were replaced with a
neutral repository root (`/opt/audit-targets/nomad-monorepo`).

Before publishing artifacts from another environment:

1. Remove user-home or workstation-specific roots (for example `/home/<user>/...`
   or `C:\Users\...`).
2. Replace paths in JSON `root`/`file` fields and report `Scope` lines with a
   neutral repository root.
