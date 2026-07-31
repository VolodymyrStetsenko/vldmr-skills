# ZK Circuit Review Report Specification

Write the report to `zk-review/report.md`. Assessment metadata, relation model,
review coverage, candidate accounting, findings/observations, limitations, and
completeness declaration are mandatory. Use `None` rather than omitting a
required section.

```markdown
# ZK Circuit Review — <project / scope>

**Status:** <No findings / Analysis observations identified / Findings identified /
Analysis incomplete>

> **Evidence classification:** Scanner flags are source-pattern matches, not
> confirmed vulnerabilities. Promote a flag to a finding only after tracing the
> constraint system and demonstrating an alternate witness or rejected valid input.

**Target revision:** <commit or `not recorded`>
**Tool:** `zk-circuit-review` <version>
**Assessment basis:** <static enumeration / source review / witness or test>
**Scope:** <paths reviewed>
**Languages:** <circom / noir / halo2>
**Reviewed:** <date>

## Constraint summary

| Metric | Count |
| --- | --- |
| Templates / functions | N |
| Input signals | N |
| Output / public signals | N |
| Equality constraints (`===` / assert) | N |
| Assign+constrain (`<==`) | N |
| Witness-only assignments (`<--` / hints) | N |

State whether witness-only assignments were traced to validating constraints.

## 1. Witness-relation model

| Public statement / output | Private inputs | Constraint dependency | Range / field assumptions | Composition assumptions |
| --- | --- | --- | --- | --- |
| <item> | <inputs> | <constraints/gates> | <explicit or unresolved> | <subcircuit/verifier/transcript> |

## 2. Review-lane coverage

| Lane | Reviewer | Scope completed | Candidates | Limitations |
| --- | --- | --- | --- | --- |
| Constraint graph | <agent or lead sequential pass> | yes/no | N | <none/details> |
| Alternate witness | ... | ... | ... | ... |
| Boundary/completeness | ... | ... | ... | ... |
| Composition | ... | ... | ... | ... |
| Independent challenge | ... | ... | ... | ... |

## 3. Candidate accounting

| ID | Origin | Location | Intended relation | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| C-... | scanner/lane | `path:line` | <relation> | E0-E3 | Finding/Observation/Rejected | <constraint evidence> |

Every scanner flag and reasoning candidate must appear exactly once.

## 4. Findings

### [Critical] <title>

- **Location:** `path:line` — `template/function`
- **Class:** <taxonomy class #>
- **Evidence:** <E2 / E3 and artifact, witness, or trace>
- **Root cause:** <one sentence, code-level>
- **Witness/PoC:** <a concrete alternate witness or rejected valid input that
  demonstrates the bug>
- **Impact:** <forge a proof / deny a valid prover / value at risk>
- **Confidence:** <High / Medium / Low, with reason>
- **Fix:** <the minimal constraint to add, shown as a diff or a single line>
- **Validation:** <test or witness required to verify the fix>

<repeat per finding, grouped by severity: Critical, High, Medium, Low>

## 5. Analysis observations

For each observation, record the location, detected condition, unresolved question,
and evidence required for classification.

## Out of scope / assumptions

- Trusted setup / verifying-key provenance (unless in scope).
- On-chain verifier binding — covered by `verifier-bridge-audit`.
- Any component you could not fully trace, with the reason.
- Any unavailable compiler, witness generator, trusted-setup artifact, or test;
  never report an unavailable check as passing.

## Completeness declaration

- Public outputs/statements traced: `<reviewed>/<in scope>`
- Witness-only assignments reviewed: `<reviewed>/<total>`
- Unconstrained regions and selector/gate families reviewed: `<reviewed>/<total>`
- Scanner flags and reasoning candidates dispositioned: `<reviewed>/<total>`
- Critical/High candidates independently challenged: `<reviewed>/<total>`
- Lanes completed: `<completed>/<required>`
- Final status basis: <why the status is supported; zero flags is not a basis>
```

Limit the report to analysis-relevant content. Do not reproduce source except
where required to establish a finding.
