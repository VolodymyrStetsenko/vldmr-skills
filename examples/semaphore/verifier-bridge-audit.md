# Verifier Bridge Audit — contracts

> VLDMR Skills · `verifier-bridge-audit` v1.2.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/semaphore/packages/contracts/contracts` · 8 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Proof-verifier contracts | 1 |
| Verifier consumers | 1 |
| Verification call sites | 1 |
| **Leads** | **0** |

**Verifiers:** `SemaphoreVerifier.sol`

**Consumers:** `Semaphore.sol`

## Integration guardrails

For each verifier consumer, three classic ZK-EVM protections are checked.

| Consumer | Replay/nullifier guard | Public-input binding |
| --- | :---: | :---: |
| `Semaphore.sol` | yes | yes |

## Leads

No integration leads. Every verifier consumer this scanner can see has replay tracking and binds public inputs to context. Confirm the binding actually covers the recipient/scope your protocol relies on.

## Verdict

**Clean surface.** No replay, unbound-input, or mutable-verifier leads were detected across verifier consumers.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Binding is inferred from the *arguments* passed to `verifyProof`; a consumer may still bind context in a way this scanner cannot see — confirm manually.
- Verifier detection covers Groth16/PLONK templates and optimized Yul verifiers; exotic custom verifiers may be missed.
