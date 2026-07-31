# Changelog

This document records externally observable changes. The project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] — 2026-07-31

### Autonomous reasoning workflows

- Upgraded all three skills from script-centered pre-audit procedures to
  autonomous, domain-specific source-review workflows.
- Added four independent reasoning lanes per skill, with parallel subagent use
  when available and mandatory isolated sequential passes otherwise.
- Added an E0-E3 Evidence Lattice: findings require a complete adversarial trace
  or stronger evidence; Critical/High candidates require independent challenge.
- Added mandatory `scope.md`, `review-ledger.md`, and final `report.md` outputs.
- Added complete candidate accounting so scanner flags and reasoning hypotheses
  cannot be silently dropped.
- Added explicit default/sentinel and initialization analysis for EVM, ordered
  statement/effect binding for verifier integrations, and witness-relation
  uniqueness/completeness analysis for circuits.

### Contracts and assurance

- Strengthened all report specifications with threat/relation models, lane
  coverage, evidence levels, candidate dispositions, and completeness gates.
- Raised skill risk tier to L2 and declared agent delegation in each security
  manifest while retaining default-deny network and target-execution controls.
- Generalized version validation to enforce SemVer consistency across
  `VERSION`, `SKILL.md`, manifests, and release tags.
- Aligned manifest, refresh-plan, security-report, and validator metadata on
  schema/tool version 2.
