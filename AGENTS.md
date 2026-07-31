# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this repo is

A small, focused library of security-audit **skills** for zero-knowledge and EVM
smart-contract systems. Each top-level directory is one self-contained skill in
the [Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)
format: a `SKILL.md` playbook, a `VERSION`, deterministic `scripts/`, and
`references/`.

| Skill | Run it when the user wants to… |
| --- | --- |
| `zk-circuit-review` | review a Circom / Noir / Halo2 circuit for soundness / under-constraint bugs |
| `verifier-bridge-audit` | audit an on-chain proof verifier and its consumers (replay, input binding, VK trust) |
| `evm-invariant-scan` | map EVM entry points / access control and derive fuzzable invariants |

## How to run a skill

1. Read that skill's `SKILL.md` fully and follow its phases in order.
2. Run its `scripts/` for the deterministic enumeration — do not hand-roll it.
3. Confirm every script flag against the real code before reporting it; anything
   unproven is a *lead*, not a finding.
4. Write the report only into the skill's output folder at the project root.

## Rules when editing this repo

- One skill, one purpose. Do not merge responsibilities.
- Scripts stay deterministic and dependency-free (Python 3 stdlib only). No
  network access in the enumeration path.
- No fabricated findings or examples anywhere.
- Bump the skill's `VERSION` and update `CHANGELOG.md` on any behavior change.
- Validate scripts against the fixtures in each `scripts/fixtures/` directory.
