# Verifier-Bridge Evidence-Lattice Workflow

The audited object is not only a verifier call. It is the end-to-end statement:
which proof, public inputs, domain, caller, action, and persistent state jointly
authorize an on-chain effect.

## Evidence levels

| Level | Requirement | Allowed classification |
| --- | --- | --- |
| E0 | Verifier-shaped pattern or unverified suspicion | Candidate only |
| E1 | Source-connected verifier-to-effect path and stated binding gap | Observation |
| E2 | Complete accepted-proof replay, substitution, trust, or ordering trace | Finding |
| E3 | Reproducible test/proof, concrete alternate input, or formal result | Confirmed finding |

## Required statement model

For every proof-consuming action, reconstruct:

1. verifier identity and verifying-key provenance;
2. proof format and all public inputs in exact order;
3. semantic meaning, encoding, and range of every public input;
4. caller-controlled action parameters and derived values;
5. chain, contract, version, epoch, recipient, amount, asset, and nonce binding;
6. nullifier or uniqueness state, including write ordering;
7. the final effect and every external interaction before uniqueness is closed.

Write the intended authorization relation as:

```text
valid_proof(statement) AND unused(unique_id) AND correct_domain
    => exactly_one_authorized_effect(statement)
```

Then attempt to vary every action-relevant value while holding the accepted
proof or statement constant.

## Independent lanes

- **Statement reconstruction:** map proof bytes and public inputs to action
  semantics field by field.
- **Replay and ordering:** attempt same-proof, same-nullifier, alternate-proof,
  reentrant, cross-contract, cross-chain, and cross-version reuse.
- **Trust and encoding:** challenge mutable verifiers/keys, initialization,
  field bounds, point encoding, hashing, packing, truncation, and aliasing.
- **Effect binding:** compare recipient, amount, asset, origin, destination,
  caller, and calldata against what the proof actually commits to.

## Candidate and challenge rules

Every candidate records location, intended property, exact public-input vector,
attacker-controlled fields, ordered attack trace, impact, evidence level, and
potential blocking controls. A challenger independently verifies verifier return
handling, uniqueness writes, inherited authorization, revert ordering, and
domain separation before promotion.

Proof-byte deduplication is insufficient evidence of replay safety when proof
encodings can vary. Absence of a variable named `nullifier` is not evidence of
replay when uniqueness is enforced through another state key.

## Completeness gate

The final report must account for every verifier, consumer, verification call,
proof-dependent effect, and candidate. `No findings` requires a completed field-
by-field binding table and replay analysis for each consumer, not zero scanner
flags.
