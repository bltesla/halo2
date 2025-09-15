use std::os::raw::c_int;

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error, SingleVerifier}, 
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, };
use rand_core::OsRng;
// Poseidon imports removed since hash computation is not needed

#[derive(Clone)]
struct VoteCircuit {
    v: Value<Fp>,        // Private vote value
    t: Value<Fp>,        // Public target value
    // h: Value<Fp>,        // Public hash of vote
    // For recursion, you'd typically also need:
    // prev_proof: Option<ProofWithPublicInputs>,
    // aggregation_data: Option<AggregationData>,
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
        Self { 
            v: Value::unknown(), 
            t: Value::unknown(), 
            // h: Value::unknown() 
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let v = meta.advice_column();
        let t = meta.instance_column();
        let sel = meta.selector();

        meta.enable_equality(v);
        meta.enable_equality(t);

        // Poseidon hash configuration removed since it's not needed

        // Gate: Check that vote equals target (v == t)
        meta.create_gate("vote equality check", |meta| {
            let s = meta.query_selector(sel);
            let vq = meta.query_advice(v, halo2_proofs::poly::Rotation::cur());
            let tq = meta.query_instance(t, halo2_proofs::poly::Rotation::cur());
            [s * (vq - tq)]
        });

        Config { v, t, sel }
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // Assign private vote value
        let v_assigned: AssignedCell<Fp, Fp> = layouter.assign_region(
            || "assign v",
            |mut region| {
                cfg.sel.enable(&mut region, 0)?;
                region.assign_advice(|| "v", cfg.v, 0, || self.v)
            },
        )?;

        // Note: Hash computation removed since it's not needed for this simple circuit
        
        Ok(())
    }
}

// MySpec struct removed since Poseidon hash is not used

// For true recursion, you would need an aggregation circuit like this:
#[derive(Clone)]
struct RecursiveVoteCircuit {
    // Current vote data
    current_vote: VoteCircuit,
    // Previous aggregated proof (for recursion)
    // prev_proof: Option<ProofWithPublicInputs>,
    // Aggregated vote count
    vote_count: Value<Fp>,
    // Running tally
    tally: Value<Fp>,
}

// Implementation would include proof verification and aggregation logic

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
        let t = v; // vote equals target (valid vote)
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Public inputs must match instance column order: [t]
        let public_inputs = vec![t];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_invalid_vote_fails() {
        let k: u32 = 7;
        let v = Fp::from(42u64);
        let t = Fp::from(99u64); // vote does NOT equal target (invalid)
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Public inputs must match instance column order: [t]
        let public_inputs = vec![t];
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        // This should fail because v != t
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_vote_circuit_proof_roundtrip() {
        let k: u32 = 7;
        let v = Fp::from(123u64);
        let t = v; // vote equals target
        // Hash computation removed since it's not needed

        let circuit = VoteCircuit {
            v: Value::known(v),
            t: Value::known(t),
        };

        // Generate proving key and verification key
        let params = Params::new(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        // Create proof
        let public_inputs = vec![t];
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        create_proof(
            &params, 
            &pk, 
            &[circuit], 
            &[&[&public_inputs]], 
            OsRng, 
            &mut transcript
        ).expect("proof generation should not fail");
        let proof = transcript.finalize();

        // Verify proof
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(verify_proof(
            &params, 
            pk.get_vk(), 
            strategy, 
            &[&[&public_inputs]], 
            &mut transcript
        ).is_ok());
    }


    #[test]
    fn test_multiple_votes_batch() {
        // Test with 3 votes: yes, no, yes
        let k: u32 = 8; // Larger circuit for multiple votes
        
        let mut votes = Vec::new();
        votes.push(Fp::from(1u64)); // yes
        votes.push(Fp::from(0u64)); // no  
        votes.push(Fp::from(1u64)); // yes
        
        let target = Fp::from(1u64); // Target is "yes"
        
        // Test each vote individually
        for (i, &vote) in votes.iter().enumerate() {
            
            let circuit = VoteCircuit {
                v: Value::known(vote),
                t: Value::known(target),
            };
            
            // Public inputs must match instance column order: [t]
            let public_inputs = vec![target];
            let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
            
            if vote == target {
                // Vote matches target - should pass
                assert_eq!(prover.verify(), Ok(()), "Vote {} (yes) should be valid", i);
            } else {
                // Vote doesn't match target - should fail
                assert!(prover.verify().is_err(), "Vote {} (no) should be invalid", i);
            }
        }
        
        // Test with target = 0 (no)
        let target_no = Fp::from(0u64);
        for (i, &vote) in votes.iter().enumerate() {
            
            let circuit = VoteCircuit {
                v: Value::known(vote),
                t: Value::known(target_no),
            };
            
            let mut public_inputs = Vec::new();
            public_inputs.push(target_no);
            let mut prover_inputs = Vec::new();
            prover_inputs.push(public_inputs);
            let prover = MockProver::run(k, &circuit, prover_inputs).unwrap();
            
            if vote == target_no {
                // Vote matches target - should pass
                assert_eq!(prover.verify(), Ok(()), "Vote {} (no) should be valid when target is no", i);
            } else {
                // Vote doesn't match target - should fail
                assert!(prover.verify().is_err(), "Vote {} (yes) should be invalid when target is no", i);
            }
        }
    }
}