# zk-review Report Template

Write the report to `zk-review/report.md`. Keep it factual and evidence-backed.
Omit any section with no content rather than padding it.

```markdown
# ZK Circuit Review — <project / scope>

**Verdict (one line):** <e.g. "One critical under-constrained output allows proof
forgery; two completeness leads pending confirmation.">

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

A high witness-only-to-constraint ratio is itself a signal; call it out if
present.

## Findings

### [Critical] <title>

- **Location:** `path:line` — `template/function`
- **Class:** <taxonomy class #>
- **Root cause:** <one sentence, code-level>
- **Witness/PoC:** <a concrete alternate witness or rejected valid input that
  demonstrates the bug>
- **Impact:** <forge a proof / deny a valid prover / value at risk>
- **Fix:** <the minimal constraint to add, shown as a diff or a single line>

<repeat per finding, grouped by severity: Critical, High, Medium, Low>

## Leads (unconfirmed)

For each: location, why it is suspicious, and exactly what evidence would confirm
or refute it. Leads are honest calibration, not filler.

## Out of scope / assumptions

- Trusted setup / verifying-key provenance (unless in scope).
- On-chain verifier binding — covered by `verifier-bridge-audit`.
- Any component you could not fully trace, with the reason.
```

Keep the whole report under ~400 lines. Depth belongs in the findings, not in
restating the source.
