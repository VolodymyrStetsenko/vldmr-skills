# Reference Analysis Artifacts

This directory contains generated JSON analysis output and corresponding
markdown summaries for selected public repositories. Artifacts are retained to
document output structure, detector behavior, and validation scope for release
`1.0.0`.

## Source Revisions

| Target | Repository | Commit |
| --- | --- | --- |
| Semaphore | `semaphore-protocol/semaphore` | `4dbc39b` |
| circomlib | `iden3/circomlib` | `35e54ea` |
| World ID contracts | `worldcoin/world-id-contracts` | `f959f72` |
| Uniswap v4 core | `Uniswap/v4-core` | `46c6834` |

## Artifact Index

| Directory | Component | JSON | Markdown |
| --- | --- | --- | --- |
| `circomlib/` | `zk-circuit-review` | `zk-circuit-review.json` | `zk-circuit-review.md` |
| `semaphore/` | `zk-circuit-review` | `zk-circuit-review.json` | `zk-circuit-review.md` |
| `semaphore/` | `verifier-bridge-audit` | `verifier-bridge-audit.json` | `verifier-bridge-audit.md` |
| `semaphore/` | `evm-invariant-scan` | `evm-invariant-scan.json` | `evm-invariant-scan.md` |
| `world-id-contracts/` | `verifier-bridge-audit` | `verifier-bridge-audit.json` | `verifier-bridge-audit.md` |
| `world-id-contracts/` | `evm-invariant-scan` | `evm-invariant-scan.json` | `evm-invariant-scan.md` |
| `uniswap-v4-core/` | `verifier-bridge-audit` | `verifier-bridge-audit.json` | `verifier-bridge-audit.md` |
| `uniswap-v4-core/` | `evm-invariant-scan` | `evm-invariant-scan.json` | `evm-invariant-scan.md` |

## Reproduction Procedure

Check out the recorded target revision and execute the applicable command from
the repository root:

```bash
python3 zk-circuit-review/scripts/enumerate_circuit.py <circuit-scope> \
  --json <output>.json --report <output>.md --no-banner

python3 verifier-bridge-audit/scripts/scan_verifier.py <solidity-scope> \
  --json <output>.json --report <output>.md --no-banner

python3 evm-invariant-scan/scripts/enumerate_evm.py <solidity-scope> \
  --json <output>.json --report <output>.md --no-banner
```

JSON records the deterministic enumeration. Markdown summarizes the same JSON
content. Report dates and absolute paths vary by environment.

## Publication Policy

`examples/` is intended to be publicly publishable. Before publishing generated
artifacts from another environment, sanitize machine-specific absolute paths
and usernames.

Required checks:

1. No user-home or workstation-specific roots (for example `/home/<user>/...`
  or `C:\\Users\\...`).
2. Paths in JSON `root` and `file` fields are replaced with neutral repository
  roots (for example `/opt/audit-targets/<repo>/...`).
3. Matching scope lines in markdown summaries are sanitized to the same neutral
  root.

A practical pre-publish check:

```bash
rg -n '/home/|/Users/|C:\\' examples --glob '!README.md'
```

No matches indicates no obvious machine-path leakage in examples.

## Interpretation

A generated flag is represented as an analysis observation until verified
against source control flow, system architecture, and intended security
properties. Zero flags indicates only that no implemented source pattern
matched within the selected scope.

Detailed coverage, observations, and limitations are recorded in
[`docs/VALIDATION.md`](../docs/VALIDATION.md).
