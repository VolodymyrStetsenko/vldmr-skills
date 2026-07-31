# Security Skills Quality Benchmark

**Assessment date:** 2026-07-31
**Repository:** `VolodymyrStetsenko/vldmr-skills`
**Assessment basis:** local source review, fixture execution, real zkSync Era execution, official specifications, and public repositories

## Executive verdict

The three skills are valid, portable Agent Skills with deterministic
standard-library evidence generators, stable JSON interfaces, domain-specific
independent reasoning lanes, evidence challenge, complete candidate accounting,
mandatory final reports, reproducible fixtures, and real-protocol evidence.
Release 2.0.0 upgrades them from script-centered pre-audit accelerators to
autonomous source-review workflows.

They are not a replacement for compilation, executable fuzzing, formal
verification, cryptographic review, or accountable human sign-off. No evidence
supports an objective claim that they are "best in the world." The defensible
goal is measurable: valid activation, complete lane execution, evidence-gated
findings, controlled failures, auditable candidate disposition, mandatory
reports, regression CI, known coverage, and reproducible results.

## Evidence collected

| Check | Result | Evidence |
| --- | --- | --- |
| Agent Skills structure | Pass | Three matching directory/name pairs with `SKILL.md`, `scripts/`, and `references/` |
| Required frontmatter | Pass | Valid names and descriptions; MIT license, compatibility, author, and version metadata |
| Fixture regression | Pass | ZK 2/2 flags, verifier 3/3 flags, EVM 10/10 flags |
| JSON stdout/file equivalence | Pass | Enforced by `tests/run_validation.py` |
| Determinism | Pass | Repeated fixture output is byte-identical |
| Invalid input handling | Pass | Exit 2 with controlled diagnostic |
| Output failure handling | Pass | Exit 2 with controlled diagnostic and no traceback |
| Real protocol execution | Pass | zkSync Era: 101 contracts, 804 functions, 263 entry points, 29 flags |
| Dynamic environment evidence | Pass, focused | `L1GatewayTests.test_chainMigrationWithUpgrade`: 1 passed with Forge-ZKsync |
| CI | Added | Python 3.9 and 3.14 regression matrix |
| Semantic completeness | Not established | Regex analyzers do not resolve inheritance, aliases, or full call graphs |
| Precision/recall measurement | Not established | Positive fixtures exist; labeled negative and mutation corpora are still needed |
| Autonomous reasoning workflow | Added in 2.0.0 | Four domain-specific independent lanes plus lead synthesis |
| Candidate/finding gate | Added in 2.0.0 | E0-E3 evidence lattice; E2+ finding threshold; challenge for Critical/High |
| Mandatory final reporting | Added in 2.0.0 | Scope, lane coverage, full ledger, evidence, limitations, completeness declaration |

## Official conformance

### Agent Skills specification and VS Code

The repository follows the required directory and frontmatter model. Names are lowercase kebab-case, match parent directories, and stay below 64 characters. Descriptions explain capability and trigger phrases. Scripts and references are colocated for progressive loading.

Personal installation should use one of the VS Code-supported locations:

- `~/.copilot/skills/`
- `~/.agents/skills/`
- `~/.claude/skills/`

Project installation should use `.github/skills/`, `.agents/skills/`, or `.claude/skills/`. Standalone source storage alone does not prove runtime discovery.

### NIST SSDF

The new regression suite and CI support repeatable verification, controlled error handling, change validation, and evidence retention. Remaining SSDF-aligned work includes release provenance, protected-branch enforcement, dependency/security scanning for CI actions, and a documented release checklist.

### OWASP Smart Contract Security

The EVM taxonomy maps partially to OWASP Smart Contract Top 10 and SCSVS categories, particularly access control, business logic, oracle manipulation, flash-loan-assisted attacks, unchecked calls, reentrancy, arithmetic review, and proxy/upgradeability. Coverage is pattern-based and must not be presented as full SCSVS verification.

For bridge-heavy protocols, future coverage should explicitly map to SCWE classes for cross-chain authenticity, replay, chain ID validation, message proof verification, token accounting, payload/gas bounds, and upgrade/storage-layout risks.

## Public benchmark comparison

| Public source | Demonstrated strengths | VLDMR status |
| --- | --- | --- |
| Trail of Bits public tools and guidance | Threat modeling, invariant-first testing, Slither static analysis, Echidna property fuzzing, evidence-oriented workflows | VLDMR 2.0 adopts threat/property modeling and evidence gates; it does not claim compiler-IR or fuzz coverage when those tools are unavailable |
| Pashov `pashov/skills` | Parallel specialist reviewers, attacker framing, concrete proof requirements, deduplication, fuzz-harness workflows | VLDMR 2.0 uses its own domain-specific Evidence-Lattice design: four lanes per niche, complete candidate ledger, E2+ findings, challenge, and mandatory reports |
| OpenZeppelin public materials | Mature secure-development guidance, upgradeability tooling, role and proxy patterns, audit reports | No public Agent Skills repository was identified in this review; compare methodology and reports, not unavailable internal automation |
| CertiK public materials | Public vulnerability research, audit reports, and security products | No public Agent Skills repository was identified in this review; internal workflow parity cannot be verified |
| Spearbit/Cantina public materials | Independent specialist review and domain-expert collaboration | VLDMR separates domain lanes and requires independent challenge for high-impact candidates |
| Consensys Diligence public tools/research | Fuzzing, formal methods, and ZK-focused testing research | VLDMR records dynamic validation as an evidence upgrade, never as completed when unavailable |

Public GitHub content does not expose the complete internal process of any audit company. Claims about private tooling or company-wide quality would be speculation.

## Highest-priority gaps

1. **Activation tests:** verify direct slash invocation and implicit trigger selection in an actual VS Code/Copilot runtime.
2. **Negative and adversarial corpora:** add guarded safe examples, inherited access-control examples, custom proxy patterns, multiline constructs, and near-miss verifier/circuit fixtures.
3. **Precision/recall accounting:** maintain labeled expected flags and expected non-flags; report regressions by detector kind.
4. **Semantic backends:** optionally consume compiler AST/build-info, Slither, or language-specific IR while retaining the dependency-free evidence fallback.
5. **Dynamic handoff:** generate Foundry invariant skeletons from catalog entries, compile them, and record build/run status.
6. **Reasoning benchmark corpus:** measure whether complete skill runs identify labeled cross-function bugs such as default-value aliasing, not only whether scripts emit flags.
7. **Coverage manifest:** map every detector to OWASP SCSVS/SCWE, known limitations, fixtures, and real-repository evidence.
8. **Release assurance:** validate with `skills-ref`, pin CI actions by commit, add release provenance, and publish immutable version tags.

## Acceptance criteria for the next release

- All skills pass official `skills-ref validate`.
- Direct and implicit activation tests pass in VS Code and at least one additional compatible runtime.
- Every detector has one positive, one negative, and one adversarial fixture.
- CI fails when zero fixtures are discovered.
- Reports include target revision, tool version, scope, evidence basis, limitations, confidence, fix validation, and clear flag/finding separation.
- Full skill runs produce `scope.md`, `review-ledger.md`, and `report.md`, and account for every scanner flag and reasoning candidate.
- Critical/High benchmark candidates receive a recorded independent challenge.
- A generated Foundry invariant harness compiles and runs on at least one real protocol.
- Real-protocol outputs are pinned to target commits and reproducible from documented commands.

## References

- VS Code: Agent Skills documentation, `https://code.visualstudio.com/docs/copilot/customization/agent-skills`
- Agent Skills specification, `https://agentskills.io/specification`
- NIST SP 800-218 SSDF, `https://doi.org/10.6028/NIST.SP.800-218`
- OWASP Smart Contract Security, `https://scs.owasp.org/`
- Trail of Bits public skills, `https://github.com/trailofbits/skills`
- Pashov Audit Group public skills, `https://github.com/pashov/skills`
- Trail of Bits Echidna, `https://github.com/crytic/echidna`
- Trail of Bits Slither, `https://github.com/crytic/slither`
- OpenZeppelin Contracts, `https://github.com/OpenZeppelin/openzeppelin-contracts`
- Spearbit portfolio, `https://github.com/spearbit/portfolio`
- Consensys Diligence, `https://diligence.security/`
- CertiK, `https://www.certik.com/`
