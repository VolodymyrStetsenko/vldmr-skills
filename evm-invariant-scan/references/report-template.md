# evm-scan Report Template

Write the report to `evm-scan/report.md`. Evidence-backed only; omit empty
sections.

```markdown
# EVM Invariant Scan — <project / scope>

**Verdict (one line):** <e.g. "One reentrancy on withdraw and a permissionless
fee setter; conservation invariant is enforced, solvency is not fuzz-covered.">

**Scope:** <paths>
**Contracts:** N   **Entry points:** N   **Permissionless:** N
**Reviewed:** <date>

## 1. Entry-point & access map

| Contract.function | Visibility | Access | Writes state | External call |
| --- | --- | --- | --- | --- |
| `Vault.withdraw` | external | permissionless | yes | yes |
| `Vault.setFee` | external | permissionless | yes | no |

Group by contract. For >30 entry points, keep permissionless ones in full and
compact the role-gated ones.

## 2. Findings

### [Critical] <title>

- **Location:** `path:line` — `function`
- **Class:** <taxonomy A/B #>
- **Root cause:** <one sentence>
- **Proof:** <statement-order trace, or the sequence of calls that breaks it>
- **Impact:** <value at risk>
- **Fix:** <minimal change>

<repeat, grouped by severity>

## 3. Invariant catalog

| ID | Invariant | On-chain | Evidence | Fuzz priority |
| --- | --- | --- | --- | --- |
| INV-1 | `Σ balances == totalAssets` | Yes | writes paired in deposit/withdraw | low |
| INV-2 | `feeBps <= MAX_BPS` at all write sites | No | `setFee` L34 unbounded | high |

For each On-chain=No invariant, include a ready-to-use property phrasing
(Foundry/Echidna/Halmos) so it can be tested immediately.

## Handoffs

- Proof-verifier binding → `verifier-bridge-audit`.
- Circuit soundness → `zk-circuit-review`.
```

Keep under ~450 lines. The invariant catalog and findings are the deliverable;
the map supports them.
