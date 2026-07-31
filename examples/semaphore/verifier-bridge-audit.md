# Verifier Bridge Audit — contracts

> VLDMR Skills · `verifier-bridge-audit` v1.0.0 · 2026-07-31 (UTC)

**Scope:** `/opt/audit-targets/semaphore/packages/contracts/contracts` · 8 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Proof-verifier contracts | 1 |
| Verifier consumers | 1 |
| Verification call sites | 1 |
| **Flags** | **0** |

**Verifiers:** `SemaphoreVerifier.sol`

**Consumers:** `Semaphore.sol`

## Integration guardrails

For each verifier consumer, three classic ZK-EVM protections are checked.

| Consumer | Replay/nullifier guard | Public-input binding |
| --- | :---: | :---: |
| `Semaphore.sol` | yes | yes |

## Analysis observations

No implemented integration-risk detection pattern matched the analyzed source. Public-input ordering, semantic equivalence, and cross-contract state transitions require separate assessment.

## Analysis status

**NO FLAGS.** No implemented replay, context-binding, or mutable-verifier detection pattern matched the analyzed source.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Binding is inferred from the *arguments* passed to `verifyProof`; a consumer may still bind context in a way this scanner cannot see — confirm manually.
- Verifier detection covers Groth16/PLONK templates and optimized Yul verifiers; exotic custom verifiers may be missed.
