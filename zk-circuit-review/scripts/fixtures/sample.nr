// Fixture for enumerate_circuit.py self-check (Noir).

// An unconstrained helper: its output MUST be re-checked in constrained code.
unconstrained fn hint_inverse(x: Field) -> Field {
    1 / x
}

fn main(x: Field, y: pub Field) {
    let inv = hint_inverse(x);
    // Re-check the hint under constraint.
    assert(x * inv == 1);
    assert_eq(y, x * x);
}
