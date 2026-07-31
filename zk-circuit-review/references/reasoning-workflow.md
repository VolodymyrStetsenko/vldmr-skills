# ZK Circuit Evidence-Lattice Workflow

The reviewed object is the witness relation implemented by constraints, not the
host-language calculation that proposes witness values. The workflow separately
tests soundness, uniqueness where required, completeness, and statement binding.

## Evidence levels

| Level | Requirement | Allowed classification |
| --- | --- | --- |
| E0 | Suspicious assignment, hint, gate, or missing-looking check | Candidate only |
| E1 | Constraint-connected path and stated unresolved property | Observation |
| E2 | Concrete alternate witness or valid input rejected by the relation | Finding |
| E3 | Reproducible witness/test, solver result, mutation, or formal proof | Confirmed finding |

## Required relation model

For every public output or statement component, record:

1. public and private inputs, outputs, advice/hints, selectors, and lookup data;
2. the intended mathematical relation and field/range assumptions;
3. constraint dependencies from witness inputs to public outputs;
4. branches, disabled gates, zero denominators, boundary values, and aliases;
5. host-language computations that are not re-constrained;
6. cross-circuit, recursive-proof, transcript, and verifier assumptions.

Do not infer a constraint from assignment syntax. Do not infer booleanity or a
small range from how a value is used. Field arithmetic is modulo the circuit
field unless a range constraint establishes otherwise.

## Independent lanes

- **Constraint graph:** trace every public output backward and every witness-only
  value forward to a validating constraint.
- **Alternate-witness attacker:** vary hints, selectors, branches, inverses,
  decompositions, and unused signals while holding the public statement fixed.
- **Boundary/completeness attacker:** test zero, one, maximum, modulus-adjacent,
  empty, duplicate, and exceptional inputs for unintended rejection or aliasing.
- **Composition attacker:** inspect subcircuits, unconstrained wrappers, recursive
  aggregation, transcript/domain binding, and assumptions exported to verifiers.

## Candidate and challenge rules

Every candidate states the intended relation, relevant constraints, a concrete
alternate witness or unresolved degree of freedom, impact, evidence level, and
disconfirmers. A challenger independently traces all constraints that may close
the degree of freedom and checks whether the proposed witness actually preserves
the public statement.

A finding requires E2 or E3. If an alternate witness cannot be concretely
specified because compilation or constraint-system data is unavailable, retain
the item as an observation and record the required validation.

## Completeness gate

The final report must account for every public output, witness-only assignment,
unconstrained region, selector/gate family, and candidate. `No findings` requires
completed independent lanes and explicit limitations; it never follows from
zero scanner flags.
