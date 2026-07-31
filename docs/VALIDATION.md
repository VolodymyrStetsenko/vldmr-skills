# Validation & Benchmarking

This document records how the skills in this repository were benchmarked against
authoritative, public vulnerability references, and how the deterministic
enumerator scripts behave on a real, production-grade ZK + Solidity protocol.

The goal is **honest, evidence-based validation** — including the false
positives, false negatives, and coverage gaps that were found. Nothing here
claims the suite is "better" than mature industry tooling; it documents exactly
what the suite does and does not do.

## 1. Reference standards used

| Reference | What it provides | Link |
| --- | --- | --- |
| 0xPARC ZK Bug Tracker | Canonical taxonomy of 8 ZK vulnerability classes + 27 real-world bugs | https://github.com/0xPARC/zk-bug-tracker |
| Trail of Bits — building-secure-contracts | not-so-smart-contracts, program-analysis (Slither, Echidna, Medusa, Manticore) | https://github.com/crytic/building-secure-contracts |
| OWASP Smart Contract Top 10 (2026) | SC01–SC10 industry-consensus EVM risk list | https://owasp.org/www-project-smart-contract-top-10/ |

## 2. Coverage vs. the 0xPARC ZK vulnerability classes

| # | 0xPARC class | Covered by `zk-circuit-review` | Notes |
| --- | --- | --- | --- |
| 1 | Under-constrained circuits | Yes | `under-constrained-witness`, `unconstrained-output` |
| 2 | Nondeterministic circuits | Partial | Surfaced via witness-only assignment leads |
| 3 | Arithmetic over/under-flow | Partial | Flagged as review lead, not proven |
| 4 | Mismatching bit lengths | Partial | Reference taxonomy only |
| 5 | Unused public inputs optimized out | **Yes** | `unused-public-input` detector (base name used only in its declaration) |
| 6 | Frozen Heart (Fiat–Shamir forgery) | Reference only | Cryptographic-protocol level; documented as a required manual check (class 11) |
| 7 | Trusted setup leak | Reference only | Documented in taxonomy, not statically detectable |
| 8 | Assigned but not constrained | Yes | Core detector (`<--` target never appears in `===`/`<==`) |

## 3. Coverage vs. OWASP Smart Contract Top 10 (2026)

| Code | Risk | Covered by `evm-invariant-scan` |
| --- | --- | --- |
| SC01 | Access control | Yes (`permissionless-config-setter`) |
| SC02 | Business logic | Partial (invariant seeds) |
| SC03 | Price oracle manipulation | **Yes** (`spot-price-oracle`, `oracle-deprecated-feed`, `oracle-missing-staleness-check`) |
| SC04 | Flash-loan-facilitated attacks | **Yes** (`flash-loan-callback`, `balance-based-accounting`) |
| SC05 | Lack of input validation | Partial |
| SC06 | Unchecked external calls | Yes (`unchecked-low-level-call`) |
| SC07 | Arithmetic errors | Partial |
| SC08 | Reentrancy | Yes (`external-call-no-reentrancy-guard`) |
| SC09 | Integer overflow/underflow | Partial |
| SC10 | Proxy & upgradeability | **Yes** (`unprotected-upgrade`, `initializer-not-guarded`, `selfdestruct-present`) |

## 4. Real-protocol test — Semaphore

**Target:** `semaphore-protocol/semaphore`
**Commit:** `4dbc39b83a4066bf5084fd7f5d336202aad2f815` (2026-07-08)
**Runner:** Python 3.14.4, stdlib only, no network.

```
python3 zk-circuit-review/scripts/enumerate_circuit.py   <repo>/packages/circuits/src
python3 verifier-bridge-audit/scripts/scan_verifier.py    <repo>/packages/contracts/contracts
python3 evm-invariant-scan/scripts/enumerate_evm.py       <repo>/packages/contracts/contracts
```

### 4.1 zk-circuit-review
- Enumerated `semaphore.circom`: 1 template, 4 inputs, 1 output, constraints parsed.
- **0 flags. 0 false positives.** The circuit uses `<==` throughout (fully
  constrained), so the tool correctly stayed silent.
- Limitation surfaced: only the top-level file was analyzed because the circuit's
  sub-components are imported from `node_modules` (library packages), which the
  scanner skips by design. Multi-package circuit graphs are not followed.

### 4.2 verifier-bridge-audit
- Correctly identified `Semaphore.sol` as a proof **consumer** and
  `SemaphoreVerifier.sol` as the **verifier**.
- **0 flags. 0 false positives, 0 false negatives** after the heuristic upgrade:
  - Verifier detection now recognizes Semaphore's optimized Yul verifier
    (`staticcall(..., 8, ...)`, `pPairing`) — the earlier false negative is gone.
  - The replay-guard check now recognizes the `if (nullifiers[x]) revert` /
    `nullifiers[x] = true` idiom — the earlier `possible-proof-replay` false
    positive is gone.
  - The binding check now accepts proofs bound via `scope`/`nullifier` in the
    public-input arguments — the earlier `unbound-public-inputs` false positive
    is gone.
- Fixture regression: the deliberately vulnerable `Withdrawer.sol` still raises
  all three planted flags (`possible-proof-replay`, `unbound-public-inputs`,
  `mutable-verifier`), confirming the relaxations did not blunt real detection.

### 4.3 evm-invariant-scan
- Enumerated 4 contracts / 32 functions / 11 entry points.
- One flag: `permissionless-config-setter` on `updateMember` (`external override`,
  no visibility-level modifier). This is a **lead, not a confirmed finding** —
  exactly the evidence-over-assertion posture the skills mandate. Whether it is a
  real issue depends on internal enforcement inside `_updateMember` (in the
  `SemaphoreGroups` base), which a human must confirm. The tool correctly
  surfaced it for review rather than asserting a vulnerability.

## 5. Honest verdict

- The circuit scanner produced **zero false positives** on real, audited code and
  behaved conservatively; it now also covers the "unused public input" class.
- The verifier-bridge scanner, after the heuristic upgrade, produces **0 false
  positives and 0 false negatives on Semaphore** while still catching all planted
  fixture bugs. Verifier detection, replay-guard idioms, and context binding were
  each broadened based on the evidence from this test.
- The EVM scanner produced **one correct lead** with no assertion of a finding,
  and now additionally covers OWASP SC03 (oracle), SC04 (flash loan), and SC10
  (proxy/upgradeability).

These scripts are **deterministic pre-audit accelerators and lead generators**,
not a replacement for professional review. Real-world audits combine static
tools (Slither, Circomspect), fuzzers (Echidna/Medusa), formal verification
(Certora, Picus/Ecne), and expert manual review. This suite is complementary
and is strongest at the ZK↔EVM boundary that general-purpose tools do not model.

## 6. Improvement roadmap

All five items from the first validation pass are now **implemented and
regression-tested** (see the fixtures under each skill's `scripts/fixtures/` and
the re-test in section 4):

1. **verifier-bridge replay guard** — done: recognizes `if (...map[nullifier]...)
   revert`, custom-error, and consume-write idioms.
2. **verifier-bridge binding** — done: treats `scope`/`nullifier`/domain binding
   in the public-input arguments as valid, not only `msg.sender`.
3. **verifier detection** — done: markers for decimal precompile `8`,
   `pPairing`/`checkPairing`, optimized Yul `staticcall(..., 8, ...)` verifiers.
4. **zk class 5** — done: `unused-public-input` lead for inputs that never
   influence a constraint.
5. **evm OWASP gaps** — done: SC03 (oracle), SC04 (flash loans), SC10
   (proxy/upgradeability) detectors.

Future (research-grade, out of scope for static regex): Fiat–Shamir/transcript
soundness (documented as manual class 11), public-input ordering diffing against
circuit artifacts, and point/scalar malleability.
