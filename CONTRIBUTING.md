# Contribution Requirements

Contributions are evaluated for analytical accuracy, deterministic behavior,
interface stability, test coverage, and documentation quality.

## Change Requirements

1. Limit each change to a defined component or shared documentation concern.
2. Preserve component independence. A top-level skill must not require runtime
  files from another skill.
3. Preserve deterministic, offline execution in `scripts/`.
4. Use the Python standard library unless a dependency is required by a
  documented analysis capability and approved before implementation.
5. Classify static detections as analysis observations unless a reproducible violation
  is established.
6. Do not include credentials, private target data, proprietary findings, or
  unauthorized source material.
7. Update the affected `VERSION`, `CHANGELOG.md`, interface documentation, and
  examples when behavior or output changes.
8. Preserve the affected `skill-manifest.json` permission contract. New file,
  network, shell, tool, dependency, or external-instruction capabilities require
  explicit security review.

## Validation Requirements

Before submitting a change:

1. Compile modified Python files with `python3 -m py_compile`.
2. Execute the affected script against every fixture in its
  `scripts/fixtures/` directory.
3. Verify that standard output remains valid JSON when no output file is
  specified.
4. Verify report generation when the change affects report content.
5. Test at least one representative external codebase for changes to detection
  logic with material false-positive or false-negative risk.
6. Document known detection limitations introduced or modified by the change.
7. Run `python3 tools/validate_skill_security.py --refresh` and review the
  pre-mutation receipt. For intentional payload changes, apply the update with
  `--refresh --apply`.
8. Run `python3 tools/validate_skill_security.py` and
  `python3 tests/run_security_validation.py`.

## Pull Request Content

A pull request must identify:

- the affected component and interface;
- the security-analysis behavior changed;
- the validation commands executed;
- expected changes to false-positive and false-negative characteristics;
- compatibility or migration considerations.

## New Components

A new component requires:

- valid Agent Skills frontmatter and an executable procedure in `SKILL.md`;
- a SemVer `VERSION` consistent with `SKILL.md` and `skill-manifest.json`;
- deterministic analysis utilities where source enumeration is required;
- a documented input and output interface;
- a threat taxonomy and report specification under `references/`;
- fixtures representing supported detections and relevant negative controls.
