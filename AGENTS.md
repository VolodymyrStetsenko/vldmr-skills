# Repository Execution Requirements

This file defines repository-level requirements for automated coding agents.

## Component Selection

| Component | Selection condition |
| --- | --- |
| `zk-circuit-review` | The scope contains Circom, Noir, or Halo2 source requiring constraint or witness analysis. |
| `verifier-bridge-audit` | The scope contains an on-chain proof verifier or a contract consuming proof-verification results. |
| `evm-invariant-scan` | The scope contains Solidity requiring entry-point, access-control, accounting, or invariant analysis. |

## Execution Requirements

1. Read the selected component's `SKILL.md` before analysis.
2. Use the bundled deterministic script for source enumeration.
3. Verify each script flag against referenced source and relevant control flow
  before classifying it as a finding.
4. Record unresolved detections as analysis observations.
5. Write artifacts only to the documented output directory unless another path
  is specified by the user.
6. State scope, exclusions, component version, and incomplete checks in the
  report.

## Repository Modification Requirements

- Preserve separation of responsibilities among components.
- Preserve standard-library-only, offline script execution.
- Update fixtures for changes to detection behavior.
- Update `VERSION` and `CHANGELOG.md` for externally observable changes.
- Do not include target credentials, confidential source, or unverified
  vulnerability claims in repository content.
