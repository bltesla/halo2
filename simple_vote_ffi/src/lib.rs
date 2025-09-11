use std::os::raw::c_int;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Circuit, ConstraintSystem, Error, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::EqAffine;
use rand_core::OsRng;

#[derive(Clone)]
struct VoteCircuit {
    // private vote bit {0,1}
    v: Value<Fp>,
    // public claimed tally increment {0,1}
    t: Value<Fp>,
}

#[derive(Clone)]
struct Config {
    v: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    t: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    sel: halo2_proofs::plonk::Selector,
}

impl Circuit<Fp> for VoteCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { v: Value::unknown(), t: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let v = meta.advice_column();
        let t = meta.instance_column();
        let sel = meta.selector();

        // Enforce: sel * (v * (1 - v)) == 0  i.e., v in {0,1}
        // And: sel * (v - t) == 0  i.e., vote equals claimed tally increment
        meta.create_gate("vote bit and equality", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::ONE);
            vec![
                s.clone() * (vq.clone() * (one.clone() - vq.clone())),
                s * (vq - tq),
            ]
        });

        Config { v, t, sel }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_region(|| "vote", |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            let _vv = region.assign_advice(|| "v", cfg.v, 0, || self.v)?;
            // Instance t is provided externally; no assignment here.
            Ok(())
        })
    }
}

#[no_mangle]
pub extern "C" fn create_simple_vote_proof(
    k: u32,
    t_public: u64,
    v_private: u64,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    if out_ptr.is_null() || out_len.is_null() { return -1; }

    let v = (v_private % 2) as u64;
    let t = (t_public % 2) as u64;

    let circuit = VoteCircuit { v: Value::known(Fp::from(v)), t: Value::known(Fp::from(t)) };

    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) { Ok(vk) => vk, Err(_) => return -1 };
    let pk = match plonk::keygen_pk(&params, vk, &circuit) { Ok(pk) => pk, Err(_) => return -1 };

    let instances: [Fp; 1] = [Fp::from(t)];
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    if plonk::create_proof(&params, &pk, &[circuit.clone()], &[&[&instances[..]]], OsRng, &mut transcript).is_err() {
        return -1;
    }
    let proof: Vec<u8> = transcript.finalize();
    let len = proof.len();
    let mut boxed = proof.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    unsafe { *out_ptr = ptr; *out_len = len; }
    0
}

#[no_mangle]
pub extern "C" fn verify_simple_vote_proof(
    k: u32,
    t_public: u64,
    proof_ptr: *const u8,
    proof_len: usize,
) -> c_int {
    let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len) };

    let circuit = VoteCircuit { v: Value::unknown(), t: Value::unknown() };
    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) { Ok(vk) => vk, Err(_) => return -1 };

    let instances: [Fp; 1] = [Fp::from(t_public % 2)];
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    match plonk::verify_proof(&params, &vk, strategy, &[&[&instances[..]]], &mut transcript) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn free_simple_vote_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 { return; }
    unsafe { let _ = Vec::from_raw_parts(ptr, len, len); }
}


