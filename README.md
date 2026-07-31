# VLDMR Security Skills

VLDMR Security Skills is a collection of Agent Skills for static security
analysis of zero-knowledge circuits, on-chain proof-verifier integrations, and
EVM smart contracts. The repository combines deterministic source enumeration
with structured analysis procedures and machine-readable output.

## Components

| Component | Analysis scope | Supported source |
| --- | --- | --- |
| [`zk-circuit-review`](zk-circuit-review/) | Signal, constraint, witness, and under-constraint analysis | Circom, Noir, Halo2/Rust |
| [`verifier-bridge-audit`](verifier-bridge-audit/) | Verifier discovery, replay protection, public-input binding, and verifier trust | Solidity |
| [`evm-invariant-scan`](evm-invariant-scan/) | Entry-point enumeration, access control, external calls, accounting surfaces, and invariant candidates | Solidity |

Each component is independently installable and contains:

- `SKILL.md`: execution procedure in the Agent Skills format;
- `skill-manifest.json`: least-privilege permissions, provenance, external
  instruction inventory, and payload integrity contract;
- `scripts/`: deterministic Python analysis utilities;
- `references/`: analysis taxonomy and report requirements;
- `VERSION`: component version.

## Requirements

- Python 3.9 or later;
- a UTF-8-capable terminal for banner rendering;
- an Agent Skills-compatible runtime for automated execution of `SKILL.md`.

The analysis scripts use only the Python standard library. They do not compile
the target, execute target code, access a network, or install dependencies.

## Skill Package Security

All components are validated against explicit security contracts aligned to
OWASP Agentic Skills Top 10 risks. The local gate checks strict manifest fields,
declared versus observed capabilities, identity and credential deny rules,
external references, Unicode/control smuggling, unsafe payload types, and
complete SHA-256 package integrity.

```bash
python3 tools/validate_skill_security.py
python3 tests/run_security_validation.py
```

The validator emits deterministic JSON or hash-bound SARIF 2.1.0. Design,
control coverage, mutation workflow, and honest limitations are documented in
[`docs/AGENTIC-SKILL-SECURITY.md`](docs/AGENTIC-SKILL-SECURITY.md).

## Installation

```bash
git clone https://github.com/VolodymyrStetsenko/vldmr-skills.git
cd vldmr-skills
```

For an Agent Skills-compatible runtime, install or reference the required
top-level component directory. Components do not depend on files from another
component.

## First-Time Quick Start

The following flow is intended for first-time users who want a deterministic
run and a clear interpretation path.

1. Clone this repository and open a terminal in `vldmr-skills`.
2. Run the local security gate:

```bash
python3 tools/validate_skill_security.py
python3 tests/run_security_validation.py
```

3. Clone a target protocol at a pinned commit and switch to that commit.
4. Execute one or more scanners from this repository against target source:

```bash
python3 zk-circuit-review/scripts/enumerate_circuit.py <path> --json out.json --report out.md --no-banner
python3 verifier-bridge-audit/scripts/scan_verifier.py <path> --json out.json --report out.md --no-banner
python3 evm-invariant-scan/scripts/enumerate_evm.py <path> --json out.json --report out.md --no-banner
```

5. Interpret output using strict terminology:
  - `flags` in JSON are machine-detected source patterns;
  - analysis observations are unverified conditions from flags or manual review;
  - findings require confirmed security-property violation evidence.
6. Preserve reproduction metadata in your report: repository URL, exact commit,
  command line, UTC run date, and scanner version.

For CLI and JSON contract details see [`docs/INTERFACES.md`](docs/INTERFACES.md).

## Command-Line Interface

The deterministic analysis stage can be invoked directly:

```bash
python3 zk-circuit-review/scripts/enumerate_circuit.py <path> \
  --json zk-review/enumeration.json \
  --report zk-review/scan-report.md

python3 verifier-bridge-audit/scripts/scan_verifier.py <path> \
  --json bridge-audit/scan.json \
  --report bridge-audit/scan-report.md

python3 evm-invariant-scan/scripts/enumerate_evm.py <path> \
  --json evm-scan/enumeration.json \
  --report evm-scan/scan-report.md
```

The banner and operational messages are written to standard error. JSON is
written to standard output when `--json` is omitted. `--no-banner` suppresses
the banner for non-interactive use.

Command syntax, exit status, stream behavior, and JSON fields are specified in
[`docs/INTERFACES.md`](docs/INTERFACES.md).

## Result Classification

The following terms are normative:

- **Flag:** a machine-readable record emitted in the JSON `flags` array when an
  implemented source pattern matches.
- **Analysis observation:** an unverified security-relevant condition derived
  from one or more flags or from manual source review.
- **Finding:** a verified security-property violation with supporting evidence.

A flag does not, by itself, establish exploitability or security impact.

| Classification | Required basis |
| --- | --- |
| Finding | A demonstrated violation with a source trace, witness, state transition, or reproducible counterexample |
| Analysis observation | A detected condition for which exploitability or intended behavior has not been established |
| Informational observation | Relevant architecture, trust, or operational information without a demonstrated violation |

Generated reports identify the analysis method and known limitations. They are
not substitutes for compilation, test execution, fuzzing, formal verification,
cryptographic review, or deployment-specific threat analysis.

## Reproducibility

For a fixed component version, identical source bytes, path selection, and CLI
options produce equivalent JSON analysis content. Report generation includes
the UTC generation date and absolute scope path; these fields are environment
dependent.

Reference executions against public repositories are available in
[`examples/`](examples/). Validation methodology and coverage are documented in
[`docs/VALIDATION.md`](docs/VALIDATION.md).

## Security and Maintenance

The security boundary and private reporting procedure are defined in
[`SECURITY.md`](SECURITY.md). Contribution requirements are defined in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

Copyright © 2026 Volodymyr Stetsenko. Distributed under the
[`MIT License`](LICENSE).
