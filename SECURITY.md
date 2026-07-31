# Security Policy

## Supported Version

Security corrections are applied to the current release on the `main` branch.

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

## Operational Requirements

- Execute analysis under a non-privileged account.
- Restrict scope to source authorized for review.
- Write output to a controlled directory with appropriate permissions.
- Review generated artifacts before transfer to external systems.
- Select repository commits or release artifacts according to the deployment's
  software-supply-chain policy.

## Vulnerability Reporting

Report vulnerabilities in the skills, scripts, output handling, or repository
supply chain through a private
[GitHub security advisory](https://github.com/VolodymyrStetsenko/vldmr-skills/security/advisories/new).

Include the affected component and version, reproduction procedure, observed
impact, and relevant deployment conditions. Do not include confidential target
source unless explicitly requested through an approved secure channel.

Reports are triaged according to exploitability, confidentiality impact,
integrity impact, availability impact, and affected deployment conditions.
