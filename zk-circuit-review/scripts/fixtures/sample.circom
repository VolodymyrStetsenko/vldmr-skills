pragma circom 2.1.0;

// Fixture for enumerate_circuit.py self-check.
// Contains one correctly constrained output and one deliberately
// under-constrained witness so the enumerator's heuristic can be verified.

template IsZero() {
    signal input in;
    signal output out;
    signal inv;

    // `inv` is witness-only: assigned but not constrained here on purpose.
    inv <-- in != 0 ? 1 / in : 0;

    // `out` is properly constrained (assign + constrain).
    out <== -in * inv + 1;
    in * out === 0;
}

template BadRange() {
    signal input value;
    signal output ok;

    // BUG (intentional): `unusedTag` is a public input that is never used in any
    // constraint, so the compiler optimizes it away (0xPARC class 5).
    signal input unusedTag;

    // BUG (intentional): `ok` is only witness-assigned, never constrained.
    // A malicious prover can set `ok` to any field element.
    ok <-- value < 100 ? 1 : 0;
}

component main = IsZero();
