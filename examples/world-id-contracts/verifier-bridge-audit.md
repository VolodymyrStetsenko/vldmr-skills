# Verifier Bridge Audit — src

> VLDMR Skills · `verifier-bridge-audit` v1.0.0 · 2026-07-31 (UTC)

**Scope:** `/home/volodymyr-sec/projects/_audit-targets/world-id-contracts/src` · 25 Solidity file(s)

## Summary

| metric | value |
| --- | ---: |
| Proof-verifier contracts | 7 |
| Verifier consumers | 4 |
| Verification call sites | 5 |
| **Flags** | **8** |

**Verifiers:** `SemaphoreVerifier.sol`, `b10.sol`, `b100.sol`, `b10.sol`, `b100.sol`, `b1200.sol`, `b600.sol`

**Consumers:** `WorldIDIdentityManagerImplV1.sol`, `WorldIDIdentityManagerImplV2.sol`, `WorldIDIdentityManagerImplV3.sol`, `WorldIDRouterImplV1.sol`

## Integration guardrails

For each verifier consumer, three classic ZK-EVM protections are checked.

| Consumer | Replay/nullifier guard | Public-input binding |
| --- | :---: | :---: |
| `WorldIDIdentityManagerImplV1.sol` | **no** | yes |
| `WorldIDIdentityManagerImplV2.sol` | **no** | **no** |
| `WorldIDIdentityManagerImplV3.sol` | **no** | **no** |
| `WorldIDRouterImplV1.sol` | **no** | yes |

## Analysis observations

The following static-analysis observations require source-level and system-level verification before classification as findings.

| # | Severity | Kind | Location | Note |
| ---: | --- | --- | --- | --- |
| 1 | Critical | `possible-proof-replay` | WorldIDIdentityManagerImplV1.sol:401 | verifier is invoked but no nullifier tracking + reject-if-used guard was found in this file — a valid proof may be replayable. Confirm where the proof/nullifier is marked consumed. |
| 2 | High | `mutable-verifier` | WorldIDIdentityManagerImplV1.sol:537 | the verifier / verifying key is settable — confirm the setter is guarded (timelock or governance), else a compromised admin can swap in a verifier that accepts forged proofs. |
| 3 | Critical | `possible-proof-replay` | WorldIDIdentityManagerImplV2.sol:140 | verifier is invoked but no nullifier tracking + reject-if-used guard was found in this file — a valid proof may be replayable. Confirm where the proof/nullifier is marked consumed. |
| 4 | High | `unbound-public-inputs` | WorldIDIdentityManagerImplV2.sol:140 | the proof's public inputs do not appear to commit to caller/recipient/scope/domain data (no msg.sender, nullifier, scope, recipient or domain-separator on the verification path) — a valid proof may be front-run or reused by another actor; confirm the binding. |
| 5 | High | `mutable-verifier` | WorldIDIdentityManagerImplV2.sol:183 | the verifier / verifying key is settable — confirm the setter is guarded (timelock or governance), else a compromised admin can swap in a verifier that accepts forged proofs. |
| 6 | Critical | `possible-proof-replay` | WorldIDIdentityManagerImplV3.sol:81 | verifier is invoked but no nullifier tracking + reject-if-used guard was found in this file — a valid proof may be replayable. Confirm where the proof/nullifier is marked consumed. |
| 7 | High | `unbound-public-inputs` | WorldIDIdentityManagerImplV3.sol:81 | the proof's public inputs do not appear to commit to caller/recipient/scope/domain data (no msg.sender, nullifier, scope, recipient or domain-separator on the verification path) — a valid proof may be front-run or reused by another actor; confirm the binding. |
| 8 | Critical | `possible-proof-replay` | WorldIDRouterImplV1.sol:351 | verifier is invoked but no nullifier tracking + reject-if-used guard was found in this file — a valid proof may be replayable. Confirm where the proof/nullifier is marked consumed. |

## Analysis status

**REVIEW REQUIRED.** 8 observation(s) are mapped to high-impact integration-risk classes and require manual verification.

## Method & limits

- Deterministic regex over comment-stripped Solidity (no compile, no network).
- Binding is inferred from the *arguments* passed to `verifyProof`; a consumer may still bind context in a way this scanner cannot see — confirm manually.
- Verifier detection covers Groth16/PLONK templates and optimized Yul verifiers; exotic custom verifiers may be missed.
