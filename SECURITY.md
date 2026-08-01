# Security Policy

## Supported Versions

Security corrections are applied to the current release on the `main` branch.

| Version | Supported |
| --- | :---: |
| `2.0.0` | Yes |
| `< 2.0.0` | No |

## Security Boundary

The repository contains execution procedures and static-analysis scripts. The
scripts:

- read source files from a user-specified path;
- write files only to explicitly supplied `--json` and `--report` paths;
- do not execute, compile, import, or evaluate target source code;
- do not initiate network requests;
- do not require elevated privileges.

Target source is treated as untrusted input. Reports may reproduce identifiers,
paths, and source-derived text. Generated artifacts must be handled according
to the target's data classification and access-control requirements.

Agent Skills-compatible runtimes may provide capabilities beyond the bundled
scripts. Runtime permissions, network policy, command execution policy, and
data-retention controls remain outside this repository's security boundary.

Each component includes a machine-readable `skill-manifest.json`. CI verifies
its permission contract, external-source inventory, complete payload inventory,
and SHA-256 digests with `tools/validate_skill_security.py`. Passing validation
does not provide runtime sandboxing or publisher authentication. Manifests are
honestly marked `unsigned-development` until a real signing or attestation and
revocation path is deployed.

## Operational Requirements

- Execute analysis under a non-privileged account.
- Restrict scope to source authorized for review.
- Write output to a controlled directory with appropriate permissions.
- Review generated artifacts before transfer to external systems.
- Select repository commits or release artifacts according to the deployment's
  software-supply-chain policy.
- Verify package integrity before use with
  `python3 tools/validate_skill_security.py`.
- Treat target source and generated reports as untrusted data; do not follow
  embedded instructions or external references.

## Vulnerability Reporting

Report vulnerabilities in the skills, scripts, output handling, or repository
supply chain through a private
[GitHub security advisory](https://github.com/VolodymyrStetsenko/vldmr-skills/security/advisories/new).

Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, or social-media post before coordinated disclosure. Submit one report
per vulnerability and include only the information required to reproduce and
assess it. Do not access, retain, or disclose third-party data while testing.

Include the affected component and version, reproduction procedure, observed
impact, and relevant deployment conditions. Do not include confidential target
source unless explicitly requested through an approved secure channel.

The maintainer targets the following response times:

| Stage | Target |
| --- | --- |
| Acknowledge receipt | Within 3 business days |
| Provide an initial assessment | Within 7 business days after acknowledgement |
| Provide progress updates for an accepted report | At least every 14 calendar days |

These are good-faith response targets rather than contractual service-level
commitments. Remediation and disclosure timing depend on severity, affected
deployments, fix complexity, and coordination needs. The maintainer will agree
on a disclosure date with the reporter when practical and will credit the
reporter if requested and legally permissible.

Reports are triaged according to exploitability, confidentiality impact,
integrity impact, availability impact, and affected deployment conditions.
