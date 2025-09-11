use wasm_bindgen::prelude::*;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::EqAffine;
use rand_core::OsRng;

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
            let _va = region.assign_advice(|| "a", cfg.a, 0, || self.a)?;
            let _vb = region.assign_advice(|| "b", cfg.b, 0, || self.b)?;
            let sum = self.a.zip(self.b).map(|(a, b)| a + b);
            let _vc = region.assign_advice(|| "c", cfg.c, 0, || sum)?;
            Ok(())
        })
    }
}

#[wasm_bindgen]
pub fn create_simple_add_proof_wasm(k: u32, a: u32, b: u32) -> Vec<u8> {
    let circuit = MyCircuit {
        a: Value::known(Fp::from(a as u64)),
        b: Value::known(Fp::from(b as u64)),
    };
    let params: Params<EqAffine> = Params::new(k);
    let vk = plonk::keygen_vk(&params, &circuit).expect("vk");
    let pk = plonk::keygen_pk(&params, vk, &circuit).expect("pk");
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    plonk::create_proof(&params, &pk, &[circuit.clone()], &[&[]], OsRng, &mut transcript).expect("prove");
    transcript.finalize()
}

#[wasm_bindgen]
pub fn verify_simple_add_proof_wasm(k: u32, a: u32, b: u32, proof: &[u8]) -> bool {
    let circuit = MyCircuit {
        a: Value::known(Fp::from(a as u64)),
        b: Value::known(Fp::from(b as u64)),
    };
    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) { Ok(vk) => vk, Err(_) => return false };
    let strategy = halo2_proofs::plonk::SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    plonk::verify_proof(&params, &vk, strategy, &[&[]], &mut transcript).is_ok()
}


