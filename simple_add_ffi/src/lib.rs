use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Circuit, ConstraintSystem, Error, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::EqAffine;

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

#[no_mangle]
pub extern "C" fn verify_simple_add_proof(
    k: u32,
    a: u64,
    b: u64,
    proof_ptr: *const u8,
    proof_len: usize,
) -> c_int {
    // Safety: caller must pass valid pointer/len.
    let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len) };

    let circuit = MyCircuit { a: Value::known(Fp::from(a)), b: Value::known(Fp::from(b)) };

    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) {
        Ok(vk) => vk,
        Err(_) => return -1,
    };
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    match plonk::verify_proof(&params, &vk, strategy, &[&[]], &mut transcript) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}


