# EVM Invariant Scan Report Specification

Write the report to `evm-scan/report.md`. Omit sections that have no applicable
content.

```markdown
# EVM Invariant Scan — <project / scope>

**Status:** <No findings / Analysis observations identified / Findings identified /
Analysis incomplete>

**Scope:** <paths>
**Contracts:** N   **Entry points:** N   **Permissionless:** N
**Reviewed:** <date>

## 1. Entry-point & access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | --- | --- |
| `Vault.sol / withdraw` | external | none detected | yes | yes |
| `Vault.sol / setFee` | external | `onlyOwner` | yes | no |

List every state-changing public or external entry point. `none detected` means
that no recognized modifier was present; it does not establish that the
function is unauthorized because authorization may occur in function bodies or
inherited code.

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

## Related analysis requirements

- Proof-verifier binding → `verifier-bridge-audit`.
- Circuit soundness → `zk-circuit-review`.
```

Limit the report to analysis-relevant content. Do not reproduce source except
where required to establish a finding or invariant.
