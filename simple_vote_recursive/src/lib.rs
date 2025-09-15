// use std::ffi::CStr;
use std::os::raw::{ c_int};

use halo2_proofs:: {
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{ Circuit, ConstraintSystem, Error, SingleVerifier}, 
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, group::ff::PrimeField};
use rand_core::OsRng;
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config, primitives as poseidon};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Spec};

#[derive(Clone)]
struct VoteCircuit {
    v: Value <Fp>,
    t: Value <Fp>,
    h: Value <Fp>,
}

#[derive(Clone)]
struct Config {
    v: halo2_proofs::plonk::Column <halo2_proofs::plonk::Advice>,
    t: halo2_proofs::plonk::Column <halo2_proofs::plonk::Instance>,
    h: halo2_proofs::plonk::Column <halo2_proofs::plonk::Instance>,
    sel: halo2_proofs::plonk::Selector,
    poseidon: Pow5Config<Fp, 3, 2>, // width 3 , rate 2
}

impl Circuit <Fp> for VoteCircuit {
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

        meta.enable_equality(v);
        meta.enable_equality(t);
        meta.enable_equality(h);

        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let partial_sbox = meta.advice_column();
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<MySpec>(meta, state, partial_sbox, rc_a, rc_b);

        meta.create_gate("vote and hash equality", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            let hq = meta.query_instance(h, halo2_proofs::poly::Rotation::cur());
            vec![s * (vq - tq)]
        });

        Config { v, t, h, sel, poseidon }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
       let v_assigned: AssignedCell<Fp, Fp> =   layouter.assign_region(
        || "assign v",
         |mut region| {
            cfg.sel.enable(&mut region, 0)?;
            region.assign_advice(|| "v", cfg.v, 0, || self.v)
            }, )?;

            let chip = Pow5Chip::<Fp, 3,2>::construct(cfg.poseidon.clone());
            let hasher = Hash::<_,_, MySpec,ConstantLength<1>,3,2>::init(
                chip,
                layouter.namespace(||"poseidon init"),
            )?;
            let output = hasher.hash(layouter.namespace(||"posiedon hash"), [v_assigned])?;
            layouter.constrain_instance(output.cell(), cfg.h, 0)?;
            
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

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::MockProver,
        plonk::{keygen_vk, keygen_pk, create_proof, verify_proof},
    };

    #[test]
    fn test_vote_circuit_mock_prover() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = v; // vote equals target
        let h = poseidon::Hash::<_, MySpec, ConstantLength<1>, 3, 2>::init().hash([v]);

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(h),
        };

        let public_inputs = vec![t, h];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_vote_circuit_proof_roundtrip() {
        let k: u32 = 7;
        let v = Fp::from(123u64);
        let t = v; // vote equals target
        let h = poseidon::Hash::<_, MySpec, ConstantLength<1>, 3, 2>::init().hash([v]);

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(h),
        };

        // Generate proving key and verification key
        let params = Params::new(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        // Create proof
        let public_inputs = vec![t, h];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[&[&public_inputs]], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof = transcript.finalize();

        // Verify proof
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[&public_inputs]], &mut transcript).is_ok());
    }

    #[test]
    fn test_vote_circuit_invalid_vote() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = Fp::from(99u64); // vote does not equal target
        let h = poseidon::Hash::<_, MySpec, ConstantLength<1>, 3, 2>::init().hash([v]);

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(h),
        };

        let public_inputs = vec![t, h];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // This should fail because v != t
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_vote_circuit_wrong_hash() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = v; // vote equals target
        let wrong_h = Fp::from(999u64); // wrong hash

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(wrong_h),
        };

        let public_inputs =vec![t, wrong_h];
        // let prover = MockProver::run(k, &circuit, public_inputs.to_vec());
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // This should fail because the hash doesn't match the vote
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_vote_circuit_zero_vote() {
        let k: u32 = 7;
        let v = Fp::from(0u64);
        let t = v; // vote equals target
        let h = poseidon::Hash::<_, MySpec, ConstantLength<1>, 3, 2>::init().hash([v]);

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(h),
        };

        let public_inputs = vec![t, h];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_vote_circuit_large_vote() {
        let k: u32 = 7;
        let v = Fp::from(0xFFFFFFFFFFFFFFFFu64); // max u64
        let t = v; // vote equals target
        let h = poseidon::Hash::<_, MySpec, ConstantLength<1>, 3, 2>::init().hash([v]);

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
            h: Value::known(h),
        };

        let public_inputs = vec![t, h];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

