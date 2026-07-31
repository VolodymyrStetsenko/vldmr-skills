<div align="center">

# Stetsenko Security Skills

**AI-driven security skills for zero-knowledge circuits, EVM smart contracts, and the fragile seam between them.**

Authored and maintained by **Volodymyr Stetsenko** ([@VolodymyrSkills](https://github.com/VolodymyrSkills))

[Skills](#skills) · [Install & Run](#install--run) · [Design principles](#design-principles) · [Security](SECURITY.md) · [License](LICENSE)

</div>

---

## Why this exists

Most modern zero-knowledge protocols are not "pure" cryptography living in a
vacuum. They are a **circuit** (Circom / Noir / Halo2 / a zkVM guest) that
proves a statement, a **verifier contract** that checks the proof on-chain, and
a body of **EVM logic** that trusts the verified public inputs to move real
value. Bugs rarely stay in one layer — the expensive ones live *between* layers:
an under-constrained signal that the circuit never notices, a public input the
verifier never binds to state, a proof that can be replayed after it was already
spent.

These skills are built around that reality. They are three focused,
composable capabilities that an AI coding agent can run directly on a codebase
to produce evidence-backed security findings — not vibes, not checklists.

## Skills

| Skill | Layer | What it does |
| --- | --- | --- |
| [`zk-circuit-review`](zk-circuit-review) | ZK core | Enumerates every signal and constraint in a Circom / Noir / Halo2 circuit and hunts under-constrained outputs, soundness and completeness gaps, and non-deterministic witnesses. |
| [`verifier-bridge-audit`](verifier-bridge-audit) | ZK ↔ EVM | Audits the on-chain proof verifier and the binding between public inputs and contract state: proof replay, input aliasing, verifying-key trust, and nullifier handling. |
| [`evm-invariant-scan`](evm-invariant-scan) | EVM core | Produces a pre-audit map of entry points, access control, and accounting invariants, and emits a machine-checkable invariant catalog to seed fuzzing and formal verification. |

Each skill is self-contained: a `SKILL.md` playbook, deterministic helper
scripts under `scripts/`, and reference taxonomies under `references/`.

## Install & Run

The skills follow the open [Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)
convention and work with any agent runtime that reads `SKILL.md` files —
**Claude Code, Cursor, GitHub Copilot, Codex, and Windsurf**.

Point your agent at this repository, then ask in natural language:

```
Install https://github.com/VolodymyrSkills/vldmr-skills and run zk-circuit-review on ./circuits
run verifier-bridge-audit on the on-chain verifier and its consuming contracts
run evm-invariant-scan on the codebase
```

Each skill writes its report into a dedicated output folder at the project root
(`zk-review/`, `bridge-audit/`, `evm-scan/`) and cleans up its own scratch
files. Nothing is written outside that folder. On start the scripts print the
VLDMR Skills banner to stderr and, with `--report`, auto-generate a
severity-ranked markdown summary alongside the JSON.

Real, unedited runs against Semaphore, circomlib, World ID, and Uniswap v4 core
are in [examples/](examples/README.md).

## Design principles

1. **Evidence over assertion.** Every finding must cite a file, a line, and a
   concrete trace, witness, or counterexample. A claim that cannot be grounded
   is downgraded to a *lead*, never presented as a fact.
2. **Determinism where it counts.** Enumeration (signals, constraints, entry
   points, state deltas) is done by scripts, not by guesswork, so the same code
   yields the same map every run.
3. **One skill, one purpose.** No mega-prompt. Each skill does one job the whole
   way through and hands clean artifacts to the next.
4. **Vendor-neutral output.** Reports never assume a contest, bounty, or
   platform framing. They read like an internal engineering review.
5. **No fabrication.** When the analysis cannot determine something, it says so.

## Repository layout

```
vldmr-skills/
├── zk-circuit-review/       # ZK circuit soundness & constraint review
├── verifier-bridge-audit/   # On-chain verifier and public-input binding audit
├── evm-invariant-scan/      # EVM entry-point & invariant pre-audit scan
├── examples/                # Real reports from real protocols (unedited)
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
└── LICENSE
```

## Contributing · Security · License

Improvements and fixes are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Report a vulnerability in the skills themselves via the [Security Policy](SECURITY.md).
Released under the [MIT License](LICENSE) © 2026 Volodymyr Stetsenko.
