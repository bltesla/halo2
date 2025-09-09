use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error},
    dev::MockProver,
};

#[derive(Clone)]
struct MyCircuit {
    a: Value<Fp>,
    b: Value<Fp>,
}

#[derive(Clone)]
struct Config {
    a: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    b: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    c: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    sel: halo2_proofs::plonk::Selector,
}


impl Circuit<Fp> for MyCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { a: Value::unknown(), b: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let sel = meta.selector();

        meta.create_gate("a + b = c", |meta| {
            let s = meta.query_selector(sel);
            let a = meta.query_advice(a, halo2_proofs::poly::Rotation::cur());
            let b = meta.query_advice(b, halo2_proofs::poly::Rotation::cur());
            let c = meta.query_advice(c, halo2_proofs::poly::Rotation::cur());
            vec![s * (a + b - c)]
        });

        Config { a, b, c, sel }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_region(|| "region", |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            let va = region.assign_advice(|| "a", cfg.a, 0, || self.a)?;
            let vb = region.assign_advice(|| "b", cfg.b, 0, || self.b)?;
            let sum = self.a.zip(self.b).map(|(a, b)| a + b);
            let _vc = region.assign_advice(|| "c", cfg.c, 0, || sum)?;
            Ok(())
        })
    }
}

fn main() {
    let circuit = MyCircuit {
        a: Value::known(Fp::from(2)),
        b: Value::known(Fp::from(3)),
    };
    let prover = MockProver::run(4, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    println!("Constraint satisfied: a + b = c");

    use halo2_proofs::{
        plonk,
        poly::commitment::Params,
        transcript::{Blake2bWrite, Challenge255},
    };
    use pasta_curves::EqAffine;
    // use rand::rngs::OsRng;
    use rand_core::OsRng;

    let k = 4;
    let params = Params::new(k);
    let vk = plonk::keygen_vk(&params, &circuit).unwrap();
    let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();
    
    let circuit_for_proof = circuit.clone();
    
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(
        &params,
        &pk,
        &[circuit_for_proof],
        &[&[]], // no public inputs
        OsRng,
        &mut transcript,
    ).unwrap();
    let proof: Vec<u8> = transcript.finalize();
    
    println!("proof size: {} bytes ({:.2} KiB)", proof.len(), proof.len() as f64 / 1024.0);
}
