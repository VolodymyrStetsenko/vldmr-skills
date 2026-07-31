# Security Skills Quality Benchmark

**Assessment date:** 2026-07-31
**Repository:** `VolodymyrStetsenko/vldmr-skills`
**Assessment basis:** local source review, fixture execution, real zkSync Era execution, official specifications, and public repositories

## Executive verdict

The three skills are valid, portable Agent Skills with deterministic standard-library analyzers, stable JSON interfaces, explicit flag/finding terminology, reproducible fixtures, and real-protocol evidence. They are suitable as pre-audit accelerators.

They are not a replacement for semantic analysis, compilation, fuzzing, formal verification, or senior review. No evidence supports an objective claim that they are "best in the world." The defensible goal is measurable: valid activation, deterministic execution, controlled failures, traceable reports, regression CI, known coverage, and reproducible findings.

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
| Trail of Bits `trailofbits/skills` | Workflow entry/exit criteria, anti-rationalization guidance, validators, self-tests, broad CI, evidence gates, specialist workers/judges | Deterministic analyzers and evidence terminology are strong; orchestration, activation tests, negative corpora, and reviewer gates are less mature |
| Pashov `pashov/skills` | Protocol x-ray, invariant synthesis, Foundry/Echidna/Medusa harness generation, campaign execution, deterministic repros, explicit build status | VLDMR is lighter and easier to run, but currently stops before automatic harness generation and campaign/repro production |
| OpenZeppelin public materials | Mature secure-development guidance, upgradeability tooling, role and proxy patterns, audit reports | No public Agent Skills repository was identified in this review; compare methodology and reports, not unavailable internal automation |
| CertiK public materials | Public vulnerability research, audit reports, and security products | No public Agent Skills repository was identified in this review; internal workflow parity cannot be verified |

Public GitHub content does not expose the complete internal process of any audit company. Claims about private tooling or company-wide quality would be speculation.

## Highest-priority gaps

1. **Activation tests:** verify direct slash invocation and implicit trigger selection in an actual VS Code/Copilot runtime.
2. **Negative and adversarial corpora:** add guarded safe examples, inherited access-control examples, custom proxy patterns, multiline constructs, and near-miss verifier/circuit fixtures.
3. **Precision/recall accounting:** maintain labeled expected flags and expected non-flags; report regressions by detector kind.
4. **Semantic backends:** optionally consume compiler AST/build-info, Slither, or language-specific IR while retaining the dependency-free fallback.
5. **Dynamic handoff:** generate Foundry invariant skeletons from catalog entries, compile them, and record build/run status.
6. **Finding gate:** require reachability, attacker control, violated property, impact, confidence, and reproduction before severity classification.
7. **Coverage manifest:** map every detector to OWASP SCSVS/SCWE, known limitations, fixtures, and real-repository evidence.
8. **Release assurance:** validate with `skills-ref`, pin CI actions by commit, add release provenance, and publish immutable version tags.

## Acceptance criteria for the next release

- All skills pass official `skills-ref validate`.
- Direct and implicit activation tests pass in VS Code and at least one additional compatible runtime.
- Every detector has one positive, one negative, and one adversarial fixture.
- CI fails when zero fixtures are discovered.
- Reports include target revision, tool version, scope, evidence basis, limitations, confidence, fix validation, and clear flag/finding separation.
- A generated Foundry invariant harness compiles and runs on at least one real protocol.
- Real-protocol outputs are pinned to target commits and reproducible from documented commands.

## References

- VS Code: Agent Skills documentation, `https://code.visualstudio.com/docs/copilot/customization/agent-skills`
- Agent Skills specification, `https://agentskills.io/specification`
- NIST SP 800-218 SSDF, `https://doi.org/10.6028/NIST.SP.800-218`
- OWASP Smart Contract Security, `https://scs.owasp.org/`
- Trail of Bits public skills, `https://github.com/trailofbits/skills`
- Pashov Audit Group public skills, `https://github.com/pashov/skills`
