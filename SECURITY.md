# Security Policy

## Scope

This policy covers the **skills in this repository** — the `SKILL.md` playbooks
and their helper scripts. It does not cover third-party protocols you analyze
with these skills.

## Reporting a vulnerability

If you discover a security issue in a skill or its scripts — for example a script
that could be coerced into executing untrusted input, writing outside its output
directory, or leaking data — please report it privately.

- Open a [GitHub security advisory](https://github.com/VolodymyrStetsenko/vldmr-skills/security/advisories/new), or
- Contact the maintainer directly before public disclosure.

Please include:

- The skill and script affected.
- A minimal reproduction.
- The impact you believe it has.

You will receive an acknowledgement, and a fix or mitigation will be
prioritized according to severity. Please give a reasonable window for a fix
before any public disclosure.

## Safe usage guidance

- Run these skills on code you are authorized to review.
- Review the helper scripts before running them in a privileged environment;
  they are intentionally small and readable.
- The skills only write into their dedicated output directory at the project
  root and clean up their own scratch files.
