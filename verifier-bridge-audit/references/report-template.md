# bridge-audit Report Template

Write the report to `bridge-audit/report.md`. Evidence-backed only. Omit empty
sections.

```markdown
# Verifier Bridge Audit — <project / scope>

**Verdict (one line):** <e.g. "Withdrawals are replayable and the recipient is
unbound — two Critical findings; verifier is admin-swappable without delay.">

**Verifier contracts:** <files>
**Consumer contracts:** <files>
**Reviewed:** <date>

## Seam overview

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

## Leads (unconfirmed)

Location, suspicion, and the exact evidence needed to confirm.

## Handoffs

- Circuit-side concerns (e.g. is a public output actually constrained?) →
  `zk-circuit-review`.
- Generic accounting / access-control issues → `evm-invariant-scan`.
```

Keep under ~400 lines. The value is in the attack traces, not in restating code.
