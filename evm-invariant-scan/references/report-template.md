# EVM Invariant Scan Report Specification

Write the report to `evm-scan/report.md`. The assessment metadata, threat model,
review coverage, candidate accounting, findings/observations, invariant catalog,
limitations, and completeness declaration are mandatory. Use `None` rather than
omitting a required section.

```markdown
# EVM Invariant Scan — <project / scope>

**Status:** <No findings / Analysis observations identified / Findings identified /
Analysis incomplete>

> **Evidence classification:** Scanner flags are source-pattern matches, not
> confirmed vulnerabilities. Promote a flag to a finding only after tracing the
> reachable state transition and demonstrating a violated security property.

**Target revision:** <commit or `not recorded`>
**Scope:** <paths>
**Tool:** `evm-invariant-scan` <version>
**Assessment basis:** <static enumeration / source review / tests / PoC>
**Contracts:** N   **Entry points:** N   **Permissionless:** N
**Reviewed:** <date>

## 1. Threat and state model

| Item | Security role | Trust / attacker control | Source evidence |
| --- | --- | --- | --- |
| Asset / liability / role / dependency / sentinel | <role> | <trusted/untrusted/configurable> | `path:line` |

State the critical state machines, initialization and upgrade assumptions, and
security meaning of zero/default values.

## 2. Entry-point & access map

| Source / function | Visibility | Access indicators | Writes state | External call |
| --- | --- | --- | --- | --- |
| `Vault.sol / withdraw` | external | none detected | yes | yes |
| `Vault.sol / setFee` | external | `onlyOwner` | yes | no |

List every state-changing public or external entry point. `none detected` means
that no recognized modifier was present; it does not establish that the
function is unauthorized because authorization may occur in function bodies or
inherited code.

## 3. Review-lane coverage

| Lane | Reviewer | Scope completed | Candidates | Limitations |
| --- | --- | --- | --- | --- |
| System/state model | <agent or lead sequential pass> | yes/no | N | <none/details> |
| Invariant attacker | ... | ... | ... | ... |
| Interaction attacker | ... | ... | ... | ... |
| Lifecycle/privilege attacker | ... | ... | ... | ... |
| Independent challenge | ... | ... | ... | ... |

## 4. Candidate accounting

| ID | Origin | Location | Property | Evidence | Disposition | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| C-... | scanner/lane | `path:line` | <property> | E0-E3 | Finding/Observation/Rejected | <specific evidence> |

Every scanner flag and reasoning candidate must appear exactly once.

## 5. Findings

### [Critical] <title>

- **Location:** `path:line` — `function`
- **Class:** <taxonomy A/B #>
- **Evidence:** <E2 / E3 and artifact or trace>
- **Root cause:** <one sentence>
- **Proof:** <statement-order trace, or the sequence of calls that breaks it>
- **Impact:** <value at risk>
- **Confidence:** <High / Medium / Low, with reason>
- **Fix:** <minimal change>
- **Validation:** <test, invariant, or reproduction required to verify the fix>

<repeat, grouped by severity>

## 6. Analysis observations

For each observation, record its candidate ID, unresolved precondition, current
evidence, and the exact test or source dependency required to resolve it.

## 7. Invariant catalog

| ID | Invariant | On-chain | Evidence | Fuzz priority |
| --- | --- | --- | --- | --- |
| INV-1 | `Σ balances == totalAssets` | Yes | writes paired in deposit/withdraw | low |
| INV-2 | `feeBps <= MAX_BPS` at all write sites | No | `setFee` L34 unbounded | high |

For each On-chain=No invariant, include a ready-to-use property phrasing
(Foundry/Echidna/Halmos) so it can be tested immediately.

## Limitations

Record excluded paths, unresolved inheritance or dynamic dispatch, unavailable
tooling, failed commands, and any claim that could not be established. Never
turn an unavailable check into a passing result.

## Related analysis requirements

- Proof-verifier binding → `verifier-bridge-audit`.
- Circuit soundness → `zk-circuit-review`.

## Completeness declaration

- State-changing entry points mapped: `<reviewed>/<in scope>`
- Scanner flags dispositioned: `<reviewed>/<total>`
- Reasoning candidates dispositioned: `<reviewed>/<total>`
- Critical/High candidates independently challenged: `<reviewed>/<total>`
- Lanes completed: `<completed>/<required>`
- Final status basis: <why the status is supported; zero flags is not a basis>
```

Limit the report to analysis-relevant content. Do not reproduce source except
where required to establish a finding or invariant.
