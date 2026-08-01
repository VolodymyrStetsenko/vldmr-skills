# Validation

Release `2.0.0` is checked by two local gates:

```bash
python3 tests/run_validation.py
python3 tests/run_security_validation.py
```

The functional suite validates Agent Skills metadata, autonomous workflow and
report contracts, deterministic fixture output, controlled failures,
documentation links, and publishable example paths.

| Skill | Expected fixture flags |
| --- | ---: |
| `zk-circuit-review` | 2 |
| `verifier-bridge-audit` | 3 |
| `evm-invariant-scan` | 10 |

The security suite validates all three manifests and exercises adversarial
AST01-AST10 cases, including undeclared instructions, permission escalation,
Unicode smuggling, unsafe payloads, symlink escapes, integrity drift, and
malformed metadata.

GitHub Actions also measures line and branch coverage for the functional and
security suites, including Python subprocesses launched by those suites. The
coverage job publishes `coverage.xml` and a browsable HTML report in the
`python-coverage` workflow artifact. Coverage measurement is a CI-only quality
control and does not add a runtime dependency to any skill package.

The worked Nomad example under [`examples/`](../examples/) demonstrates the
full workflow against a pinned real-protocol revision. Fixture and example
results apply only to their recorded source and scope; they do not establish
complete vulnerability coverage.
