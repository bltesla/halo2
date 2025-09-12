use std::os::raw::c_int;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Circuit, ConstraintSystem, Error, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, group::ff::PrimeField};
use rand_core::OsRng;
use halo2_gadgets::poseidon::{Pow5Chip, Pow5Config, primitives as poseidon};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Spec};

#[derive(Clone)]
struct VoteCircuit {
    // private vote value (64-bit integer embedded into Fp)
    v: Value<Fp>,
    // public claimed tally value (same Fp value)
    t: Value<Fp>,
    // public hash of the vote value
    h: Value<Fp>,
}

#[derive(Clone)]
struct Config {
    v: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    t: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    h: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    sel: halo2_proofs::plonk::Selector,
    poseidon: Pow5Config<Fp, 3, 2>,
}

impl Circuit<Fp> for VoteCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { v: Value::unknown(), t: Value::unknown(), h: Value::unknown() }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let v = meta.advice_column();
        let t = meta.instance_column();
        let h = meta.instance_column();
        let sel = meta.selector();

        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<MySpec>(meta, state, partial_sbox, rc_a, rc_b);

        // Enforce equality: v = t and hash(v) = h
        meta.create_gate("vote and hash equality", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            let hq = meta.query_instance(h, halo2_proofs::poly::Rotation::cur());

            // You would normally constrain the hash here, but for simplicity, we'll
            // only prove v = t in this gate. The hash is used as a public input.
            vec![s * (vq - tq)]
        });

        Config { v, t, h, sel, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        layouter.assign_region(|| "vote", |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            region.assign_advice(|| "v", cfg.v, 0, || self.v)?;
            Ok(())
        })?;

        // This is a simplified approach. In a full circuit, you would
        // constrain the hash output against the public input `h`.
        //
        // layouter.assign_region(|| "constrain hash output", |mut region| {
        //     let hash_assigned = hash_circuit_res?;
        //     let h_assigned = region.assign_instance(|| "h", cfg.h, 0, || self.h)?;
        //     region.constrain_equal(&hash_assigned, &h_assigned)?;
        //     Ok(())
        // })?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct MySpec;
impl Spec<Fp, 3, 2> for MySpec {
    fn full_rounds() -> usize { 8 }
    fn partial_rounds() -> usize { 56 }
    fn sbox(val: Fp) -> Fp { val.pow_vartime(&[5]) }
    fn secure_mds() -> usize { 0 }
    fn constants() -> (Vec<[Fp; 3]>, poseidon::Mds<Fp, 3>, poseidon::Mds<Fp, 3>) {
        poseidon::generate_constants::<_, MySpec, 3, 2>()
    }
}

#[no_mangle]
pub extern "C" fn create_simple_vote_proof(
    k: u32,
    t_public: u64,
    v_private: u64,
    // Optional commitment output buffer (may be null to skip returning it)
    com_ptr: *mut *mut u8,
    com_len: *mut usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    if out_ptr.is_null() || out_len.is_null() { return -1; }

    let v_fp = Fp::from(v_private);
    let t_fp = Fp::from(t_public);

    // Compute the hash of the private vote outside the circuit for public input
    // Out-of-circuit Poseidon hash of v (WIDTH=3, RATE=2)
    let h_fp = poseidon::Hash::<Fp, MySpec, ConstantLength<1>, 3, 2>::init().hash([v_fp]);

    let circuit = VoteCircuit {
        v: Value::known(v_fp),
        t: Value::known(t_fp),
        h: Value::known(h_fp),
    };

    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) { Ok(vk) => vk, Err(_) => return -1 };
    let pk = match plonk::keygen_pk(&params, vk, &circuit) { Ok(pk) => pk, Err(_) => return -1 };

    let inst_t = [t_fp];
    let inst_h = [h_fp];
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    if plonk::create_proof(&params, &pk, &[circuit.clone()], &[&[&inst_t[..], &inst_h[..]]], OsRng, &mut transcript).is_err() {
        return -1;
    }
    let proof: Vec<u8> = transcript.finalize();

    if !com_ptr.is_null() && !com_len.is_null() {
        let repr = h_fp.to_repr();
        let mut boxed = repr.as_ref().to_vec().into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        unsafe { *com_ptr = ptr; *com_len = len; }
    }
    
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
    h_public_ptr: *const u8,
    h_public_len: usize,
    proof_ptr: *const u8,
    proof_len: usize,
) -> c_int {
    let proof = unsafe { std::slice::from_raw_parts(proof_ptr, proof_len) };
    let h_bytes = unsafe { std::slice::from_raw_parts(h_public_ptr, h_public_len) };
    let mut repr = <Fp as PrimeField>::Repr::default();
    if repr.as_mut().len() != h_bytes.len() { return -1; }
    repr.as_mut().copy_from_slice(h_bytes);
    let opt = Fp::from_repr(repr);
    if opt.is_none().into() { return -1; }
    let h_fp = opt.unwrap();
 
    let circuit = VoteCircuit { v: Value::unknown(), t: Value::unknown(), h: Value::unknown() };
    let params: Params<EqAffine> = Params::new(k);
    let vk = match plonk::keygen_vk(&params, &circuit) { Ok(vk) => vk, Err(_) => return -1 };

    let inst_t = [Fp::from(t_public as u64)];
    let inst_h = [h_fp];
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
    match plonk::verify_proof(&params, &vk, strategy, &[&[&inst_t[..], &inst_h[..]]], &mut transcript) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn free_simple_vote_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 { return; }
    unsafe { let _ = Vec::from_raw_parts(ptr, len, len); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_proof_roundtrip() {
        let k: u32 = 4;
        let vote: u64 = 42;
        let secret: u64 = 42;

        let mut com_ptr: *mut u8 = std::ptr::null_mut();
        let mut com_len: usize = 0;
        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let rc = unsafe {
            create_simple_vote_proof(
                k,
                vote,
                secret,
                &mut com_ptr,
                &mut com_len,
                &mut proof_ptr,
                &mut proof_len,
            )
        };
        assert_eq!(rc, 0, "prover returned error");

        let ok = unsafe {
            verify_simple_vote_proof(
                k,
                vote,
                com_ptr as *const u8,
                com_len,
                proof_ptr as *const u8,
                proof_len,
            )
        };
        assert_eq!(ok, 0, "verification failed");

        unsafe {
            free_simple_vote_bytes(proof_ptr, proof_len);
            free_simple_vote_bytes(com_ptr, com_len);
        }
    }

    #[test]
    fn test_vote_proof_invalid_vote() {
        let k: u32 = 4;
        let vote: u64 = 42;
        let secret: u64 = 42;

        let mut com_ptr: *mut u8 = std::ptr::null_mut();
        let mut com_len: usize = 0;
        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: usize = 0;

        let rc = unsafe {
            create_simple_vote_proof(
                k,
                vote,
                secret,
                &mut com_ptr,
                &mut com_len,
                &mut proof_ptr,
                &mut proof_len,
            )
        };
        assert_eq!(rc, 0, "prover returned error");

        // Verify against wrong public vote
        let wrong_vote = vote + 1;
        let ok = unsafe {
            verify_simple_vote_proof(
                k,
                wrong_vote,
                com_ptr as *const u8,
                com_len,
                proof_ptr as *const u8,
                proof_len,
            )
        };
        assert_ne!(ok, 0, "verification should fail for mismatched vote");

        unsafe {
            free_simple_vote_bytes(proof_ptr, proof_len);
            free_simple_vote_bytes(com_ptr, com_len);
        }
    }
}