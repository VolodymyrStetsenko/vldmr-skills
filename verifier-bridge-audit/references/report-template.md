# Verifier Bridge Audit Report Specification

Write the report to `bridge-audit/report.md`. Omit sections that have no
applicable content.

```markdown
# Verifier Bridge Audit — <project / scope>

**Status:** <No findings / Analysis observations identified / Findings identified /
Analysis incomplete>

**Verifier contracts:** <files>
**Consumer contracts:** <files>
**Reviewed:** <date>

## Integration overview

| Consumer | Call site | Nullifier tracking | Input binding | VK source |
| --- | --- | --- | --- | --- |
| `Contract.fn` | `file:line` | yes/no | bound/unbound (which fields) | immutable/settable |

## Findings

### [Critical] <title>

- **Location:** `path:line` — `function`
- **Class:** <threat #>
- **Root cause:** <one sentence>
- **Attack trace:**
  1. Tx 1: <what the attacker submits>
  2. Tx 2 (or reentrant call): <how the same proof / unbound field is abused>
- **Impact:** <funds drained / proof forged / griefing>
- **Fix:** <minimal change — e.g. "record `nullifierHashes[nf] = true` before
  `transfer`, and add `recipient` to the public inputs">

<repeat per finding, grouped by severity>

## Analysis observations

For each observation, record the location, detected condition, unresolved question,
and evidence required for classification.

## Related analysis requirements

- Circuit-side concerns (e.g. is a public output actually constrained?) →
  `zk-circuit-review`.
- Generic accounting / access-control issues → `evm-invariant-scan`.
```

Limit the report to analysis-relevant content. Do not reproduce source except
where required to establish a finding.
