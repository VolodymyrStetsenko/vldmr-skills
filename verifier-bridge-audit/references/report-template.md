# Verifier Bridge Audit Report Specification

Write the report to `bridge-audit/report.md`. Assessment metadata, statement and
binding model, review coverage, candidate accounting, findings/observations,
limitations, and completeness declaration are mandatory. Use `None` rather than
omitting a required section.

```markdown
# Verifier Bridge Audit — <project / scope>

**Status:** <No findings / Analysis observations identified / Findings identified /
Analysis incomplete>

> **Evidence classification:** Scanner flags are source-pattern matches, not
> confirmed vulnerabilities. Promote a flag to a finding only after tracing the
> verifier call, public-input binding, replay state, and reachable impact.

**Target revision:** <commit or `not recorded`>
**Tool:** `verifier-bridge-audit` <version>
**Assessment basis:** <static enumeration / source review / tests / PoC>
**Verifier contracts:** <files>
**Consumer contracts:** <files>
**Reviewed:** <date>

## 1. Statement and integration model

| Consumer / effect | Call site | Ordered public inputs | Action fields | Uniqueness | Domain binding | Verifier / VK trust |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Contract.fn` / <effect> | `file:line` | `[field0, ...]` | <recipient/amount/...> | <mechanism> | <chain/contract/version> | <immutable/settable/...> |

## 2. Review-lane coverage

| Lane | Reviewer | Scope completed | Candidates | Limitations |
| --- | --- | --- | --- | --- |
| Statement reconstruction | <agent or lead sequential pass> | yes/no | N | <none/details> |
| Replay/ordering | ... | ... | ... | ... |
| Trust/encoding | ... | ... | ... | ... |
| Effect binding | ... | ... | ... | ... |
| Independent challenge | ... | ... | ... | ... |

## 3. Candidate accounting

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| C-... | scanner/lane | `path:line` | <property> | E0-E3 | Finding/Observation/Rejected | <specific evidence> |

Every scanner flag and reasoning candidate must appear exactly once.

## 4. Findings

### [Critical] <title>

- **Location:** `path:line` — `function`
- **Class:** <threat #>
- **Evidence:** <E2 / E3 and artifact or trace>
- **Root cause:** <one sentence>
- **Attack trace:**
  1. Tx 1: <what the attacker submits>
  2. Tx 2 (or reentrant call): <how the same proof / unbound field is abused>
- **Impact:** <funds drained / proof forged / griefing>
- **Confidence:** <High / Medium / Low, with reason>
- **Fix:** <minimal change — e.g. "record `nullifierHashes[nf] = true` before
  `transfer`, and add `recipient` to the public inputs">
- **Validation:** <test, alternate witness, or reproduction required to verify the fix>

<repeat per finding, grouped by severity>

## 5. Analysis observations

For each observation, record the location, detected condition, unresolved question,
and evidence required for classification.

## Limitations

Record excluded paths, unresolved inheritance or call targets, unavailable
circuit/public-input specifications, failed commands, and any claim that could
not be established. Never turn an unavailable check into a passing result.

## Related analysis requirements

- Circuit-side concerns (e.g. is a public output actually constrained?) →
  `zk-circuit-review`.
- Generic accounting / access-control issues → `evm-invariant-scan`.

## Completeness declaration

- Verifiers reviewed: `<reviewed>/<in scope>`
- Consumers and proof-dependent effects reviewed: `<reviewed>/<in scope>`
- Verification call sites field-mapped: `<reviewed>/<total>`
- Scanner flags and reasoning candidates dispositioned: `<reviewed>/<total>`
- Critical/High candidates independently challenged: `<reviewed>/<total>`
- Lanes completed: `<completed>/<required>`
- Final status basis: <why the status is supported; zero flags is not a basis>
```

Limit the report to analysis-relevant content. Do not reproduce source except
where required to establish a finding.
