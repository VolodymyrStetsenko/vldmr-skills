# Skills

Autonomous Agent Skills for source-level security review of EVM contracts,
proof-verifier integrations, and zero-knowledge circuits.

Each skill combines deterministic source enumeration with independent reasoning
lanes, adversarial challenge, complete candidate accounting, and a mandatory
final report. Scanner flags are evidence inputs, not findings.

## Skills

| Skill | Scope |
| --- | --- |
| [`evm-invariant-scan`](evm-invariant-scan/) | EVM entry points, state transitions, authorization, accounting, callbacks, initialization, and upgrades |
| [`verifier-bridge-audit`](verifier-bridge-audit/) | Proof-to-EVM statement binding, replay, trust, encoding, and effects |
| [`zk-circuit-review`](zk-circuit-review/) | Circuit constraints, alternate witnesses, boundaries, completeness, and composition |

All three packages are version `2.0.0`, require Python 3.9+, and use only the
Python standard library for deterministic enumeration. By default they do not
execute target code or access the network.

## Install

```bash
git clone https://github.com/VolodymyrStetsenko/vldmr-skills.git
cd vldmr-skills
```

Install or reference the required top-level skill directory from an Agent
Skills-compatible runtime. The packages are independent.

## Run

Invoke a skill by name and provide a source scope, for example:

```text
Run evm-invariant-scan on ./contracts and write the final report.
```

The agent executes the full workflow without treating scanner output as a
verdict:

```text
deterministic enumeration
  -> independent reasoning lanes
  -> evidence-lattice challenge
  -> mandatory report
```

Artifacts are written under `evm-scan/`, `bridge-audit/`, or `zk-review/` in the
target project. Every complete run includes:

- `scope.md`: revision, included and excluded paths, and commands;
- machine-readable deterministic evidence;
- `review-ledger.md`: every candidate and its disposition;
- `report.md`: threat model, confirmed findings, observations, limitations, and
  completeness declaration.

## Evidence model

| Level | Meaning |
| --- | --- |
| E0 | Source pattern or unsupported hypothesis |
| E1 | Source-connected property and reachable path |
| E2 | Complete adversarial trace or concrete counterexample |
| E3 | Executable test, fuzz result, symbolic result, or formal proof |

A finding requires E2 or E3. E0/E1 items remain observations. Critical and High
findings require an independent challenge pass.

## Deterministic utilities

The Phase 1 utilities can also be run directly:

```bash
python3 evm-invariant-scan/scripts/enumerate_evm.py <solidity-path> --json out.json --report out.md
python3 verifier-bridge-audit/scripts/scan_verifier.py <solidity-path> --json out.json --report out.md
python3 zk-circuit-review/scripts/enumerate_circuit.py <circuit-path> --json out.json --report out.md
```

These commands enumerate source patterns only. Their generated markdown is not
the final audit report.

## Validation

```bash
python3 tools/validate_skill_security.py
python3 tests/run_validation.py
python3 tests/run_security_validation.py
```

The security validator checks least-privilege manifests, declared capabilities,
external references, unsafe payloads, Unicode/control smuggling, and SHA-256
package integrity. It emits deterministic JSON or SARIF 2.1.0.

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the validation contract and
[`docs/INTERFACES.md`](docs/INTERFACES.md) for deterministic CLI details.

## Worked example

[`examples/`](examples/) contains one complete v2 audit of the Nomad bridge at a
pinned pre-incident revision. The skill independently rediscovered the zero-root
vulnerability behind the August 2022 exploit and recorded a complete E2 attack
trace.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

Copyright © 2026 Volodymyr Stetsenko. Distributed under the
[`MIT License`](LICENSE).
