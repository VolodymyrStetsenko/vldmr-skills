// Fixture for enumerate_circuit.py self-check (Halo2, structural).

use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Selector};

struct MyConfig {
    a: Column<Advice>,
    s: Selector,
}

fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig {
    let a = meta.advice_column();
    let s = meta.selector();

    meta.create_gate("mul", |meta| {
        let s = meta.query_selector(s);
        let a = meta.query_advice(a, Rotation::cur());
        vec![s * (a.clone() * a)]
    });

    MyConfig { a, s }
}

fn assign(region: &mut Region<F>, config: &MyConfig) {
    config.s.enable(region, 0).unwrap();
    region.assign_advice(|| "a", config.a, 0, || Value::known(F::ONE)).unwrap();
}
